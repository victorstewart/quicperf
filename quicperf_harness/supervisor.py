from __future__ import annotations

import os
import resource
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Sequence


class SupervisionError(RuntimeError):
    pass


def _enter_network_namespace(network_namespace_fd: int) -> None:
    try:
        os.setns(network_namespace_fd, os.CLONE_NEWNET)
    finally:
        os.close(network_namespace_fd)


def _prepare_child(
    log_limit: int,
    cpu_affinity: tuple[int, ...] | None,
    cgroup: Path | None,
    network_namespace_fd: int | None,
) -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (log_limit, log_limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if network_namespace_fd is not None:
        _enter_network_namespace(network_namespace_fd)
    if cpu_affinity is not None:
        os.sched_setaffinity(0, cpu_affinity)
    if cgroup is not None:
        (cgroup / "cgroup.procs").write_text("0", encoding="ascii")


@dataclass
class ManagedProcess:
    process: subprocess.Popen[bytes]
    control: socket.socket
    log: BinaryIO
    pidfd: int | None

    def alive(self) -> bool:
        return self.process.poll() is None

    def terminate(self, term_seconds: float = 2.0, kill_seconds: float = 1.0) -> int:
        if self.process.poll() is not None:
            return int(self.process.returncode)
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            return self.process.wait(timeout=term_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                return self.process.wait(timeout=kill_seconds)
            except subprocess.TimeoutExpired as exc:
                raise SupervisionError("process group survived TERM-to-KILL cleanup") from exc

    def close(self) -> None:
        self.control.close()
        self.log.close()
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None


class Supervisor:
    def __init__(self, log_limit_bytes: int = 1_048_576):
        if log_limit_bytes < 4_096:
            raise ValueError("log limit is too small")
        self.log_limit_bytes = log_limit_bytes
        self.processes: list[ManagedProcess] = []

    def spawn(
        self,
        command: Sequence[str],
        *,
        log_path: Path,
        cwd: Path,
        environment: dict[str, str] | None = None,
        pass_control_argument: bool = False,
        cpu_affinity: Iterable[int] | None = None,
        cgroup: Path | None = None,
        network_namespace: Path | None = None,
    ) -> ManagedProcess:
        if not command or not Path(command[0]).is_file() or not os.access(command[0], os.X_OK):
            raise SupervisionError("configured endpoint is missing or nonexecutable")
        affinity = tuple(sorted(set(cpu_affinity))) if cpu_affinity is not None else None
        if affinity is not None and (not affinity or any(cpu < 0 for cpu in affinity)):
            raise SupervisionError("CPU affinity must contain nonnegative CPU IDs")
        if cgroup is not None and not (cgroup / "cgroup.procs").is_file():
            raise SupervisionError(f"cgroup is not ready: {cgroup}")
        namespace_fd: int | None = None
        if network_namespace is not None:
            if not hasattr(os, "setns") or not hasattr(os, "CLONE_NEWNET"):
                raise SupervisionError("Python runtime lacks direct network setns support")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        child.set_inheritable(True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log = log_path.open("xb")
        env = os.environ.copy()
        if environment:
            env.update(environment)
        env["QUICPERF_CONTROL_FD"] = str(child.fileno())
        try:
            if network_namespace is not None:
                try:
                    namespace_fd = os.open(
                        network_namespace, os.O_RDONLY | os.O_CLOEXEC
                    )
                except OSError as exc:
                    raise SupervisionError(
                        f"network namespace is unavailable: {network_namespace}: {exc}"
                    ) from exc
            child_command = list(command)
            if pass_control_argument:
                child_command.append(f"--control-fd={child.fileno()}")
            process = subprocess.Popen(
                child_command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                pass_fds=(
                    (child.fileno(),)
                    if namespace_fd is None
                    else (child.fileno(), namespace_fd)
                ),
                start_new_session=True,
                preexec_fn=lambda: _prepare_child(
                    self.log_limit_bytes, affinity, cgroup, namespace_fd
                ),
            )
        except BaseException:
            parent.close()
            child.close()
            log.close()
            raise
        finally:
            if namespace_fd is not None:
                os.close(namespace_fd)
        child.close()
        try:
            pidfd = os.pidfd_open(process.pid, 0)
        except (AttributeError, OSError):
            pidfd = None
        managed = ManagedProcess(process, parent, log, pidfd)
        self.processes.append(managed)
        return managed

    def cleanup(self) -> None:
        failures = []
        for managed in reversed(self.processes):
            try:
                managed.terminate()
            except SupervisionError as exc:
                failures.append(str(exc))
            finally:
                managed.close()
        self.processes.clear()
        if failures:
            raise SupervisionError("; ".join(failures))

    def __enter__(self) -> "Supervisor":
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.cleanup()

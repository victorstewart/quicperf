"""Process-isolated Tctl and APERF/MPERF cadence sampler."""

from __future__ import annotations

import argparse
import ctypes
import os
import select
import signal
import socket
import struct
import time

from quicperf_harness.health import AmdPerfCounterReader


MESSAGE = struct.Struct("=cqqqi")
COUNTER_MESSAGE = struct.Struct("=cqqqqi")
STARTED = b"S"
TEMPERATURE_SAMPLE = b"T"
COUNTER_SAMPLE = b"C"
STOPPED = b"X"
STOP = b"Q"
ERROR = b"E"


def _send_error(channel: socket.socket, error: BaseException) -> None:
    try:
        channel.send(ERROR + f"{type(error).__name__}: {error}".encode())
    except OSError:
        pass


def run(
    *,
    channel_fd: int,
    cpu: int,
    input_path: str,
    period_ns: int,
    counter_cpus: tuple[int, ...],
    counter_period_ns: int,
    priority: int,
    parent_pid: int,
) -> int:
    channel = socket.socket(fileno=channel_fd)
    temperature_fd = -1
    counter_reader: AmdPerfCounterReader | None = None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
        if os.getppid() != parent_pid:
            raise RuntimeError("temperature watchdog parent exited during startup")
        os.sched_setaffinity(0, {cpu})
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(priority))
        if (
            os.sched_getaffinity(0) != {cpu}
            or os.sched_getscheduler(0) != os.SCHED_FIFO
            or os.sched_getparam(0).sched_priority != priority
        ):
            raise RuntimeError("temperature watchdog scheduling did not stick")
        temperature_fd = os.open(input_path, os.O_RDONLY | os.O_CLOEXEC)
        counter_reader = AmdPerfCounterReader(counter_cpus)
        channel.setblocking(False)
        value = int(os.pread(temperature_fd, 64, 0).decode().strip())
        if value <= 0:
            raise RuntimeError("Tctl must be positive")
        started_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        sequence = 0
        channel.send(MESSAGE.pack(STARTED, sequence, started_ns, value, cpu))
        sequence += 1
        before = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        counters = counter_reader.read()
        after = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        counter_ns = before + (after - before) // 2
        for counter_cpu, (aperf, mperf) in counters.items():
            channel.send(
                COUNTER_MESSAGE.pack(
                    COUNTER_SAMPLE,
                    sequence,
                    counter_ns,
                    aperf,
                    mperf,
                    counter_cpu,
                )
            )
            sequence += 1
        next_temperature = started_ns + period_ns // 2
        next_counter = counter_ns + counter_period_ns
        while True:
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            next_sample = min(next_temperature, next_counter)
            timeout = max(0.0, min((next_sample - now) / 1_000_000_000, 0.02))
            readable, _, _ = select.select((channel,), (), (), timeout)
            if readable:
                command = channel.recv(1)
                if command == STOP:
                    break
                raise RuntimeError("temperature watchdog received an invalid command")
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            if now < next_sample:
                continue
            if now >= next_temperature:
                value = int(os.pread(temperature_fd, 64, 0).decode().strip())
                if value <= 0:
                    raise RuntimeError("Tctl must be positive")
                raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                channel.send(
                    MESSAGE.pack(
                        TEMPERATURE_SAMPLE, sequence, raw_ns, value, cpu
                    )
                )
                sequence += 1
                while next_temperature <= raw_ns:
                    next_temperature += period_ns
            if now >= next_counter:
                before = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                counters = counter_reader.read()
                after = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                counter_ns = before + (after - before) // 2
                for counter_cpu, (aperf, mperf) in counters.items():
                    channel.send(
                        COUNTER_MESSAGE.pack(
                            COUNTER_SAMPLE,
                            sequence,
                            counter_ns,
                            aperf,
                            mperf,
                            counter_cpu,
                        )
                    )
                    sequence += 1
                while next_counter <= counter_ns:
                    next_counter += counter_period_ns
        channel.send(
            MESSAGE.pack(
                STOPPED,
                sequence,
                time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
                0,
                cpu,
            )
        )
        return 0
    except BaseException as error:
        _send_error(channel, error)
        return 2
    finally:
        if counter_reader is not None:
            counter_reader.close()
        if temperature_fd >= 0:
            os.close(temperature_fd)
        channel.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel-fd", type=int, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--input-path", required=True)
    parser.add_argument("--period-ns", type=int, required=True)
    parser.add_argument("--counter-cpu", type=int, action="append", required=True)
    parser.add_argument("--counter-period-ns", type=int, required=True)
    parser.add_argument("--priority", type=int, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    arguments = parser.parse_args()
    return run(
        channel_fd=arguments.channel_fd,
        cpu=arguments.cpu,
        input_path=arguments.input_path,
        period_ns=arguments.period_ns,
        counter_cpus=tuple(arguments.counter_cpu),
        counter_period_ns=arguments.counter_period_ns,
        priority=arguments.priority,
        parent_pid=arguments.parent_pid,
    )


if __name__ == "__main__":
    raise SystemExit(main())

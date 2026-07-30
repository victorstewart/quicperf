from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FakePath:
    fail_at: str | None = None
    created: bool = False
    armed: bool = False
    cleaned: bool = False
    calls: list[str] = field(default_factory=list)

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            raise RuntimeError(f"fake path fault at {name}")

    def create_session(self) -> None:
        self._call("create")
        self.created = True

    def arm(self, _trace: object) -> None:
        self._call("arm")
        if not self.created:
            raise RuntimeError("arm before create")
        self.armed = True

    def reset_trial(self) -> None:
        self._call("reset")
        self.armed = False

    def cleanup(self) -> None:
        self._call("cleanup")
        self.created = False
        self.armed = False
        self.cleaned = True

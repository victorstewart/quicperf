from __future__ import annotations

from dataclasses import dataclass, field


class InjectedFault(RuntimeError):
    pass


@dataclass
class FaultInjector:
    faults: dict[str, int] = field(default_factory=dict)
    visits: dict[str, int] = field(default_factory=dict)

    def arm(self, point: str, occurrence: int = 1) -> None:
        if not point or occurrence < 1:
            raise ValueError("fault point and positive occurrence are required")
        self.faults[point] = occurrence

    def visit(self, point: str) -> None:
        count = self.visits.get(point, 0) + 1
        self.visits[point] = count
        if self.faults.get(point) == count:
            raise InjectedFault(f"injected fault at {point} occurrence {count}")

    def before_transition(self, source: str, target: str) -> None:
        self.visit(f"transition:{source}->{target}:before")

    def after_transition(self, source: str, target: str) -> None:
        self.visit(f"transition:{source}->{target}:after")


NO_FAULTS = FaultInjector()

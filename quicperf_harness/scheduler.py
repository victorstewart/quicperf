"""Pure scheduling helpers for frozen v2 benchmark plans.

This module deliberately owns no persistence or process execution.  It turns
already-frozen identifiers into deterministic lane assignments and selects the
one inferential member of a primary/retry microblock pair.
"""

from __future__ import annotations

import hashlib
import hmac
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Hashable, Iterable, Mapping, Sequence


class ScheduleError(ValueError):
    """Raised when a frozen schedule or its observed outcomes are inconsistent."""


@dataclass(frozen=True)
class LaneItem:
    item_id: str
    group: Hashable


def _initial_lane(seed: bytes, item_id: str, lane_count: int) -> int:
    digest = hmac.new(seed, b"lane" + bytes.fromhex(item_id), hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % lane_count


def balanced_lane_assignments(
    items: Iterable[LaneItem], campaign_seed: bytes, lane_count: int
) -> dict[str, int]:
    """Assign lanes by HMAC, then make the minimum number of balancing moves.

    Balance is applied independently per ``group`` (normally session and retry
    slot), because those groups are the units that can actually execute
    concurrently.  Moving one item from an overfull lane to an underfull lane
    reduces the L1 distance to a balanced allocation by two, so the greedy
    excess-to-deficit pass makes the minimum possible number of moves.
    """

    if lane_count <= 0:
        raise ScheduleError("lane_count must be positive")
    grouped: dict[Hashable, list[LaneItem]] = defaultdict(list)
    seen: set[str] = set()
    for item in items:
        if item.item_id in seen:
            raise ScheduleError(f"duplicate lane item {item.item_id}")
        seen.add(item.item_id)
        grouped[item.group].append(item)

    result: dict[str, int] = {}
    for group in sorted(grouped, key=repr):
        group_items = sorted(grouped[group], key=lambda item: item.item_id)
        lanes = {
            item.item_id: _initial_lane(campaign_seed, item.item_id, lane_count)
            for item in group_items
        }
        count = Counter(lanes.values())
        quotient, remainder = divmod(len(group_items), lane_count)

        # Give the larger target counts to lanes already closest to needing
        # them, with lane number as the stable equal-key rule.
        target: dict[int, int] = {lane: quotient for lane in range(lane_count)}
        preferred = sorted(range(lane_count), key=lambda lane: (-count[lane], lane))
        for lane in preferred[:remainder]:
            target[lane] += 1

        deficits = [
            lane
            for lane in range(lane_count)
            for _ in range(max(0, target[lane] - count[lane]))
        ]
        excess_items = [
            item_id
            for lane in range(lane_count)
            for item_id in sorted(
                (item_id for item_id, assigned in lanes.items() if assigned == lane),
                reverse=True,
            )[: max(0, count[lane] - target[lane])]
        ]
        if len(deficits) != len(excess_items):
            raise ScheduleError("internal lane balancing cardinality mismatch")
        for item_id, lane in zip(excess_items, deficits, strict=True):
            lanes[item_id] = lane
        result.update(lanes)
    return result


TERMINAL_COMPLETE = "committed"
TERMINAL_DIAGNOSTIC = {
    "unsupported",
    "invalid",
    "failed",
    "interrupted",
    "cancelled",
    "superseded_incomplete_microblock",
}


@dataclass(frozen=True)
class MicroblockOutcome:
    logical_id: str
    microblock_id: str
    slot: str
    state: str
    committed_trial_ids: tuple[str, ...] = ()
    expected_trial_ids: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return (
            self.state == TERMINAL_COMPLETE
            and len(self.committed_trial_ids) == len(self.expected_trial_ids)
            and set(self.committed_trial_ids) == set(self.expected_trial_ids)
        )


def select_inferential_microblocks(
    outcomes: Sequence[MicroblockOutcome],
) -> dict[str, MicroblockOutcome]:
    """Select exactly one complete primary or activated retry per logical block.

    Partial blocks are retained by callers for diagnostics but never returned
    for inference.  A complete retry supersedes its primary.  Two complete
    members of the same slot or an inferential primary plus retry is an
    integrity error rather than an opportunity to choose favorable data.
    """

    by_logical: dict[str, list[MicroblockOutcome]] = defaultdict(list)
    seen_ids: set[str] = set()
    for outcome in outcomes:
        if outcome.slot not in {"primary", "retry"}:
            raise ScheduleError(f"invalid microblock slot {outcome.slot!r}")
        if outcome.microblock_id in seen_ids:
            raise ScheduleError(f"duplicate microblock outcome {outcome.microblock_id}")
        seen_ids.add(outcome.microblock_id)
        by_logical[outcome.logical_id].append(outcome)

    selected: dict[str, MicroblockOutcome] = {}
    for logical_id, members in by_logical.items():
        complete = [member for member in members if member.complete]
        primaries = [member for member in complete if member.slot == "primary"]
        retries = [member for member in complete if member.slot == "retry"]
        if len(primaries) > 1 or len(retries) > 1:
            raise ScheduleError(f"multiple complete members for {logical_id}")
        if retries:
            if primaries and primaries[0].state != "superseded_incomplete_microblock":
                raise ScheduleError(f"complete primary and retry both inferential for {logical_id}")
            selected[logical_id] = retries[0]
        elif primaries:
            selected[logical_id] = primaries[0]
    return selected


def lane_count_spread(assignments: Mapping[str, int]) -> int:
    if not assignments:
        return 0
    counts = Counter(assignments.values())
    return max(counts.values()) - min(counts.values())

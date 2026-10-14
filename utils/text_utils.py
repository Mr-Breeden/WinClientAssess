from __future__ import annotations

import bisect


def newline_offsets(text: str):
    """Return line-start offsets for O(log n) match-offset to line-number lookup."""
    starts = [0]
    starts.extend(index + 1 for index, char in enumerate(text) if char == "\n")
    return starts


def line_number(starts, offset: int) -> int:
    return bisect.bisect_right(starts, int(offset or 0))

"""Simple count-min sketch stub for rate limiting."""

from __future__ import annotations


class CountMinSketch:
    """Lightweight stub for rate-limiting and approximate counting."""

    def __init__(self, width: int = 1000, depth: int = 3) -> None:
        self.width = width
        self.depth = depth
        self._counts = [{} for _ in range(depth)]

    def add(self, key: str, count: int = 1) -> None:
        for bucket in self._counts:
            bucket[key] = bucket.get(key, 0) + count

    def estimate(self, key: str) -> int:
        return min(bucket.get(key, 0) for bucket in self._counts)

    def reset(self) -> None:
        self._counts = [{} for _ in range(self.depth)]

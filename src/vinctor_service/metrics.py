from __future__ import annotations

import threading

# Standard Prometheus duration buckets (seconds). Fixed per process so every
# label set of a histogram shares the same boundaries.
_DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

_LabelKey = tuple[str, tuple[tuple[str, str], ...]]


class Metrics:
    """Per-process, thread-safe counter and histogram set rendered as Prometheus text."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[_LabelKey, int] = {}
        # key -> [per-bucket counts (non-cumulative), sum, count]
        self._histograms: dict[_LabelKey, list] = {}

    def increment(self, name: str, *, amount: int = 1, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def observe(self, name: str, value: float, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            state = self._histograms.get(key)
            if state is None:
                state = [[0] * len(_DEFAULT_BUCKETS), 0.0, 0]
                self._histograms[key] = state
            for i, bound in enumerate(_DEFAULT_BUCKETS):
                if value <= bound:
                    state[0][i] += 1
                    break
            state[1] += value
            state[2] += 1

    def render(self) -> str:
        with self._lock:
            counter_items = sorted(self._counters.items())
            histogram_items = sorted(
                (key, (list(state[0]), state[1], state[2]))
                for key, state in self._histograms.items()
            )
        lines: list[str] = []
        seen_types: set[str] = set()
        for (name, labels), value in counter_items:
            if name not in seen_types:
                lines.append(f"# TYPE {name} counter")
                seen_types.add(name)
            lines.append(f"{name}{_render_labels(labels)} {value}")
        for (name, labels), (bucket_counts, total, count) in histogram_items:
            if name not in seen_types:
                lines.append(f"# TYPE {name} histogram")
                seen_types.add(name)
            cumulative = 0
            for bound, bucket_count in zip(_DEFAULT_BUCKETS, bucket_counts, strict=True):
                cumulative += bucket_count
                le = (("le", format(bound, "g")),)
                lines.append(f"{name}_bucket{_render_labels(labels + le)} {cumulative}")
            inf = (("le", "+Inf"),)
            lines.append(f"{name}_bucket{_render_labels(labels + inf)} {count}")
            lines.append(f"{name}_sum{_render_labels(labels)} {total}")
            lines.append(f"{name}_count{_render_labels(labels)} {count}")
        return "\n".join(lines) + "\n"


def _render_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"

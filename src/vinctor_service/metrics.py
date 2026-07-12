from __future__ import annotations

import threading


class Metrics:
    """Per-process, thread-safe counter set rendered as Prometheus text."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}

    def increment(self, name: str, *, amount: int = 1, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def render(self) -> str:
        with self._lock:
            items = sorted(self._counters.items())
        lines: list[str] = []
        seen_types: set[str] = set()
        for (name, labels), value in items:
            if name not in seen_types:
                lines.append(f"# TYPE {name} counter")
                seen_types.add(name)
            if labels:
                label_str = ",".join(f'{k}="{v}"' for k, v in labels)
                lines.append(f"{name}{{{label_str}}} {value}")
            else:
                lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"

import time


class Progress:
    """Prints an updating status line every 2 seconds (checked every 10k packets)."""

    _CHECK = 10_000

    def __init__(self) -> None:
        self._n = 0
        self._t0 = self._tlast = time.monotonic()
        self._printed = False

    def tick(self, **counts) -> None:
        self._n += 1
        if self._n % self._CHECK != 0:
            return
        now = time.monotonic()
        if now - self._tlast < 2.0:
            return
        self._tlast = now
        self._render(now, counts)

    def done(self, **counts) -> None:
        if self._printed:
            self._render(time.monotonic(), counts, end='\n')

    def _render(self, now: float, counts: dict, end: str = '') -> None:
        elapsed = now - self._t0
        rate = self._n / elapsed / 1_000 if elapsed > 0 else 0
        parts = [f'{int(elapsed):>5}s', f'{self._n:>12,} pkts', f'({rate:.0f}k/s)']
        for label, value in counts.items():
            parts.append(f'{value:>6,} {label}')
        print('\r  ' + '  '.join(parts) + '   ', end=end, flush=True)
        self._printed = True

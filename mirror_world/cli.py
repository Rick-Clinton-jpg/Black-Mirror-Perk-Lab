"""Command-line entry point: score a real sandbox trace against all six
articles and exit non-zero on any violation, so this can gate a CI job or
a live sandbox run.

Usage:
    python -m mirror_world.cli path/to/trace.jsonl
    python -m mirror_world.cli --partial-ok path/to/trace.jsonl
    python -m mirror_world.cli --require-chain path/to/trace.jsonl
    python -m mirror_world.cli --expected-head HEX [--expected-count N] path/to/trace.jsonl

By default exit status is 0 only on a full PASS (all six articles evaluated
and green). With --partial-ok, exit 0 when every *evaluated* article passed
even if some articles were inapplicable (PARTIAL). FAIL always exits 1.

Governor-written traces are hash-chained and always verified. --require-chain
also refuses a legacy unchained trace. --expected-head (and optionally
--expected-count) check the trace against a checkpoint saved from
RealGovernor.trace_checkpoint(), which detects truncation. A broken chain or
mismatched checkpoint exits 2, like any other unreadable trace.
"""

from __future__ import annotations

import sys

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.trace import TraceParseError

USAGE = (
    "usage: python -m mirror_world.cli [--partial-ok] [--require-chain] "
    "[--expected-head HEX [--expected-count N]] <trace.jsonl>"
)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    partial_ok = require_chain = False
    expected_head: str | None = None
    expected_count: int | None = None
    paths: list[str] = []
    while args:
        arg = args.pop(0)
        if arg == "--partial-ok":
            partial_ok = True
        elif arg == "--require-chain":
            require_chain = True
        elif arg in ("--expected-head", "--expected-count"):
            if not args:
                print(USAGE, file=sys.stderr)
                return 2
            value = args.pop(0)
            if arg == "--expected-head":
                expected_head = value
            else:
                try:
                    expected_count = int(value)
                except ValueError:
                    print(USAGE, file=sys.stderr)
                    return 2
        else:
            paths.append(arg)
    if len(paths) != 1:
        print(USAGE, file=sys.stderr)
        return 2

    try:
        engine = MirrorConstitutionEngine.from_trace(
            paths[0], require_chain=require_chain,
            expected_head=expected_head, expected_count=expected_count,
        )
    except (TraceParseError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = engine.run()
    print(report.summary())
    verdict = report.verdict()
    if verdict == "PASS":
        return 0
    if verdict == "PARTIAL" and partial_ok:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

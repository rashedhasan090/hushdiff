from __future__ import annotations

import argparse
import json
import subprocess
import sys

from .redact import redact_diff


def _run_git_diff(extra_args: list[str]) -> str:
    cmd = ["git", "diff", *extra_args] if extra_args else ["git", "diff", "HEAD"]
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"hushdiff: git not found ({exc})") from exc
    if proc.returncode not in (0, 1):
        # git diff returns 1 when differences exist with --exit-code; without
        # that flag, non-zero usually means failure.
        err = (proc.stderr or "").strip() or f"git exited {proc.returncode}"
        raise SystemExit(f"hushdiff: {err}")
    return proc.stdout


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hushdiff",
        description=(
            "Mask secret-shaped tokens in a git unified diff so the patch is "
            "safer to paste into LLM/agent chats."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit a single JSON object on stdout with keys 'diff' and 'summary'.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the human summary on stderr (ignored with --json).",
    )
    p.add_argument(
        "git_args",
        nargs=argparse.REMAINDER,
        help="Optional args passed to `git diff` (use `--` then git flags).",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    git_args = list(args.git_args)
    if git_args and git_args[0] == "--":
        git_args = git_args[1:]

    raw = _run_git_diff(git_args)
    redacted, summary = redact_diff(raw)

    if args.json:
        print(json.dumps({"diff": redacted, "summary": summary.as_dict()}, indent=2))
        return

    sys.stdout.write(redacted)
    if not args.quiet:
        parts = [f"{k}={v}" for k, v in sorted(summary.counts.items())]
        detail = ", ".join(parts) if parts else "none"
        print(
            f"hushdiff: redacted {summary.total} token(s) ({detail})",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()

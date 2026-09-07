# hushdiff

**Mask secret-shaped tokens in git diffs** so a patch is safer to paste into LLM / agent chats.

Most secret tools scan repos or block commits. `hushdiff` does something different: it takes a normal unified diff and rewrites only the secret-*shaped* spans, keeping the rest of the patch readable for review and agent context.

Offline. No network. MIT.

## Why this is novel

- **Diff-native redaction** — works on the patch you are about to share, not the whole tree.
- **Family-aware masks** — keeps a short hint (`ghp_****REDACTED****…`, `[REDACTED:jwt]`) so humans and agents still know *what kind* of secret was removed.
- **Agent-ready output** — human mode (diff on stdout, summary on stderr) or `--json` for pipelines.

Distinct from [tokpack](https://github.com/rashedhasan090/tokpack) (token-budget packing), [sandclock](https://github.com/rashedhasan090/sandclock) (timeboxed command + fs delta), and [rippleguard](https://github.com/rashedhasan090/rippleguard) (exec surface mapping).

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# working tree vs HEAD (default)
hushdiff

# any git diff args after --
hushdiff -- HEAD~1..HEAD
hushdiff -- --cached

# machine-readable
hushdiff --json
```

### Demo on a fixture patch

```bash
python - <<'PY'
from pathlib import Path
from hushdiff import redact_diff
text = Path("examples/sample.patch").read_text()
out, summary = redact_diff(text)
print(out)
print(summary.as_dict())
PY
```

You should see GitHub/AWS/password-shaped values replaced, with a non-zero redaction count.

## What it masks

| Family | Example shape |
|--------|----------------|
| `aws_access_key` | `AKIA…` |
| `github_pat` | `ghp_…`, `gho_…`, `github_pat_…` |
| `slack_token` | `xoxb-…` |
| `jwt` | three base64url segments |
| `private_key_block` | PEM private key blocks |
| `secret_assignment` | `api_key=` / `password=` / `token=` / `secret=` values |

This is a **heuristic shield for paste safety**, not a guarantee. Prefer real secret scanning in CI for enforcement.

## License

MIT

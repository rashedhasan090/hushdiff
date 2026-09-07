from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from hushdiff.cli import main


def test_json_mode(capsys):
    fake_diff = '+api_key="supersecretvalue123"\n'
    with patch("hushdiff.cli._run_git_diff", return_value=fake_diff):
        main(["--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "diff" in payload and "summary" in payload
    assert "supersecretvalue123" not in payload["diff"]
    assert payload["summary"]["total"] >= 1


def test_git_failure_exits(capsys):
    with patch(
        "hushdiff.cli.subprocess.run",
        return_value=type(
            "P",
            (),
            {"returncode": 128, "stdout": "", "stderr": "fatal: not a git repository"},
        )(),
    ):
        with pytest.raises(SystemExit) as ei:
            main([])
    assert "fatal" in str(ei.value).lower() or "hushdiff" in str(ei.value).lower()

"""Tests for fleetctl CLI interface."""

import json
import pytest
from fleetctl.cli import main


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "0.1.0" in captured.out


def test_cli_no_args_exit_code_2(capsys):
    code = main([])
    assert code == 2


def test_cli_invalid_arg_exit_code_2():
    with pytest.raises(SystemExit) as exc:
        main(["--nonexistent-flag"])
    assert exc.value.code == 2


def test_cli_dispatch_json(capsys):
    secret = "test-secret"
    code = main(["dispatch", "-t", "node-1", "-c", "echo hello", "-s", secret, "-j"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["target"] == "node-1"
    assert data["cmd"] == "echo hello"
    assert "signature" in data


def test_cli_agent_init(capsys):
    code = main(["agent", "-i", "node-42", "-s", "my-secret"])
    assert code == 0
    captured = capsys.readouterr()
    assert "node-42 initialized" in captured.out


def test_cli_audit_verify(tmp_path, capsys):
    log_file = str(tmp_path / "audit.jsonl")
    # Empty log file should verify cleanly
    code = main(["audit", "-f", log_file, "--verify-chain"])
    assert code == 0
    captured = capsys.readouterr()
    assert "verified" in captured.out.lower()


def test_cli_tunnel_status(capsys):
    code = main(["tunnel", "-s", "test-secret", "--status"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "configured"

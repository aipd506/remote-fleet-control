"""Tests for fleetctl.agent (command execution and agent engine)."""

import sys
import pytest
from fleetctl.agent import FleetAgent, execute_command
from fleetctl.dispatcher import create_signed_payload


def test_execute_command_success():
    cmd = f'"{sys.executable}" -c "print(\'fleet_ok\')"'
    res = execute_command(cmd)
    assert res["exit_code"] == 0
    assert "fleet_ok" in res["stdout"]
    assert res["timed_out"] is False
    assert res["duration_ms"] >= 0


def test_execute_command_failure():
    cmd = f'"{sys.executable}" -c "import sys; sys.exit(42)"'
    res = execute_command(cmd)
    assert res["exit_code"] == 42
    assert res["timed_out"] is False


def test_execute_command_timeout():
    # Execute a command that sleeps longer than timeout
    cmd = f'"{sys.executable}" -c "import time; time.sleep(5)"'
    res = execute_command(cmd, timeout=1)
    assert res["timed_out"] is True
    assert res["exit_code"] == 124
    assert "timed out" in res["stderr"]


def test_agent_process_valid_dispatch():
    secret = "agent-secret-key"
    agent = FleetAgent(agent_id="node-test-1", secret=secret)
    
    cmd = f'"{sys.executable}" -c "print(\'agent_exec_ok\')"'
    payload = create_signed_payload(target="node-test-1", cmd=cmd, secret=secret)
    
    res = agent.process_dispatch(payload)
    assert res["status"] == "success"
    assert res["exit_code"] == 0
    assert "agent_exec_ok" in res["stdout"]


def test_agent_process_broadcast_dispatch():
    secret = "agent-secret-key"
    agent = FleetAgent(agent_id="node-test-1", secret=secret)
    
    cmd = f'"{sys.executable}" -c "print(\'broadcast_ok\')"'
    payload = create_signed_payload(target="*", cmd=cmd, secret=secret)
    
    res = agent.process_dispatch(payload)
    assert res["status"] == "success"
    assert res["exit_code"] == 0
    assert "broadcast_ok" in res["stdout"]


def test_agent_rejects_target_mismatch():
    secret = "agent-secret-key"
    agent = FleetAgent(agent_id="node-test-1", secret=secret)
    
    payload = create_signed_payload(target="node-other-99", cmd="echo hello", secret=secret)
    res = agent.process_dispatch(payload)
    assert res["status"] == "ignored"
    assert res["exit_code"] == 1


def test_agent_rejects_invalid_signature():
    agent = FleetAgent(agent_id="node-test-1", secret="correct-secret")
    
    payload = create_signed_payload(target="node-test-1", cmd="echo hello", secret="wrong-secret")
    res = agent.process_dispatch(payload)
    assert res["status"] == "error"
    assert res["exit_code"] == 3

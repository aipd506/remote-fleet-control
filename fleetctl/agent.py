"""
Command execution daemon and agent engine with stdout/stderr capture.
"""

import os
import subprocess
import time
from typing import Any, Dict, Optional

from fleetctl.dispatcher import verify_signed_payload, NonceCache


def execute_command(
    cmd: str,
    workdir: Optional[str] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Execute a shell/system command and capture execution metadata.
    Returns: {
        "exit_code": int,
        "stdout": str,
        "stderr": str,
        "duration_ms": float,
        "timed_out": bool
    }
    """
    start_time = time.monotonic()
    timed_out = False
    stdout = ""
    stderr = ""
    exit_code = 0

    cwd = workdir if workdir and os.path.isdir(workdir) else None

    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration_ms = (time.monotonic() - start_time) * 1000.0
        stdout = proc.stdout
        stderr = proc.stderr
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as e:
        duration_ms = (time.monotonic() - start_time) * 1000.0
        timed_out = True
        exit_code = 124
        stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = f"Command timed out after {timeout} seconds"
    except Exception as e:
        duration_ms = (time.monotonic() - start_time) * 1000.0
        exit_code = 1
        stderr = str(e)

    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": round(duration_ms, 2),
        "timed_out": timed_out,
    }


class FleetAgent:
    """
    Fleet Agent node that verifies and executes dispatched commands.
    """

    def __init__(
        self,
        agent_id: str,
        secret: str,
        workdir: str = ".",
        heartbeat_interval: int = 15,
        nonce_cache: Optional[NonceCache] = None,
    ) -> None:
        self.agent_id = agent_id
        self.secret = secret
        self.workdir = os.path.abspath(workdir)
        self.heartbeat_interval = heartbeat_interval
        self.nonce_cache = nonce_cache or NonceCache()

    def process_dispatch(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify incoming signed dispatch payload and execute if valid.
        """
        is_valid, reason = verify_signed_payload(
            payload, self.secret, nonce_cache=self.nonce_cache
        )
        if not is_valid:
            return {
                "command_id": payload.get("command_id", "unknown"),
                "status": "error",
                "error": f"Authentication/verification error: {reason}",
                "exit_code": 3,
                "stdout": "",
                "stderr": reason or "Verification failed",
                "duration_ms": 0.0,
            }

        target = payload.get("target")
        if target != "*" and target != self.agent_id:
            return {
                "command_id": payload.get("command_id"),
                "status": "ignored",
                "error": f"Target mismatch (expected {self.agent_id}, got {target})",
                "exit_code": 1,
                "stdout": "",
                "stderr": "Target mismatch",
                "duration_ms": 0.0,
            }

        cmd = payload.get("cmd", "")
        timeout = payload.get("timeout", 30)

        exec_res = execute_command(cmd, workdir=self.workdir, timeout=timeout)
        result = {
            "command_id": payload.get("command_id"),
            "agent_id": self.agent_id,
            "status": "success" if exec_res["exit_code"] == 0 else "failed",
            "exit_code": exec_res["exit_code"],
            "stdout": exec_res["stdout"],
            "stderr": exec_res["stderr"],
            "duration_ms": exec_res["duration_ms"],
            "timed_out": exec_res["timed_out"],
        }
        return result

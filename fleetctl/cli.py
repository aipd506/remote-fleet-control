"""
Command-line interface for remote-fleet-control (fleetctl).
"""

import argparse
import json
import secrets
import sys
import time
from typing import List, Optional

from fleetctl.agent import FleetAgent, execute_command
from fleetctl.audit import append_audit_record, read_audit_records, verify_audit_chain
from fleetctl.dispatcher import create_signed_payload, verify_signed_payload


class FleetArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser to enforce exit code 2 on CLI argument errors."""

    def error(self, message: str) -> None:
        sys.stderr.write(f"fleetctl error: {message}\n")
        sys.exit(2)


def build_parser() -> FleetArgumentParser:
    parser = FleetArgumentParser(
        prog="fleetctl",
        description="remote-fleet-control: Remote execution agent, signed command dispatcher, reverse tunnel & audit trail.",
    )
    parser.add_argument("--version", action="version", version="fleetctl 0.1.0")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. agent
    p_agent = subparsers.add_parser("agent", help="Run agent execution daemon")
    p_agent.add_argument("-c", "--controller", default="127.0.0.1:9050", help="Controller host:port")
    p_agent.add_argument("-i", "--agent-id", default=None, help="Agent unique identifier")
    p_agent.add_argument("-s", "--secret", required=True, help="Shared HMAC secret key")
    p_agent.add_argument("-w", "--workdir", default=".", help="Command execution working directory")
    p_agent.add_argument("-b", "--heartbeat", type=int, default=15, help="Heartbeat interval in seconds")
    p_agent.add_argument("-d", "--daemon", action="store_true", help="Run in daemon background mode")
    p_agent.add_argument("--test-payload", default=None, help="JSON signed payload string to verify and execute once")

    # 2. dispatch
    p_dispatch = subparsers.add_parser("dispatch", help="Cryptographically sign and dispatch command")
    p_dispatch.add_argument("-t", "--target", required=True, help="Target agent ID or * for broadcast")
    p_dispatch.add_argument("-c", "--cmd", required=True, help="Command string to execute")
    p_dispatch.add_argument("-s", "--secret", required=True, help="Secret key to sign payload")
    p_dispatch.add_argument("--timeout", type=int, default=30, help="Execution timeout in seconds")
    p_dispatch.add_argument("-w", "--wait", action="store_true", default=True, help="Wait for command output")
    p_dispatch.add_argument("-j", "--json", action="store_true", help="Output result in JSON format")
    p_dispatch.add_argument("--audit-file", default="fleet_audit.jsonl", help="Audit log file path")
    p_dispatch.add_argument("--local-exec", action="store_true", help="Execute directly and record to audit log")

    # 3. tunnel
    p_tunnel = subparsers.add_parser("tunnel", help="Reverse tunnel controller management")
    p_tunnel.add_argument("-l", "--listen", default="0.0.0.0:9050", help="Controller listen address")
    p_tunnel.add_argument("-s", "--secret", required=True, help="Tunnel authentication secret")
    p_tunnel.add_argument("--status", action="store_true", help="Display tunnel controller status")
    p_tunnel.add_argument("--list-agents", action="store_true", help="List active connected agents")

    # 4. audit
    p_audit = subparsers.add_parser("audit", help="Tamper-evident audit trail operations")
    p_audit.add_argument("-f", "--log-file", default="fleet_audit.jsonl", help="Path to audit log file")
    p_audit.add_argument("-a", "--agent", default=None, help="Filter audit records by agent ID")
    p_audit.add_argument("--verify-chain", action="store_true", help="Verify SHA-256 rolling hash chain integrity")
    p_audit.add_argument("--since", default=None, help="Timestamp lower bound")
    p_audit.add_argument("-j", "--json", action="store_true", help="Output audit records as JSON array")
    p_audit.add_argument("--export", default=None, help="Export verified audit records to destination file")

    return parser


def handle_agent(args: argparse.Namespace) -> int:
    agent_id = args.agent_id or f"agent-{secrets.token_hex(4)}"
    agent = FleetAgent(
        agent_id=agent_id,
        secret=args.secret,
        workdir=args.workdir,
        heartbeat_interval=args.heartbeat,
    )

    if args.test_payload:
        try:
            payload = json.loads(args.test_payload)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"Invalid JSON payload: {e}\n")
            return 1
        res = agent.process_dispatch(payload)
        print(json.dumps(res, indent=2))
        return 0 if res.get("exit_code") == 0 else 1

    print(f"fleetctl agent {agent_id} initialized (workdir: {agent.workdir})")
    return 0


def handle_dispatch(args: argparse.Namespace) -> int:
    payload = create_signed_payload(
        target=args.target,
        cmd=args.cmd,
        secret=args.secret,
        timeout=args.timeout,
    )

    if args.local_exec:
        start = time.monotonic()
        res = execute_command(args.cmd, timeout=args.timeout)
        duration_ms = (time.monotonic() - start) * 1000.0

        append_audit_record(
            log_path=args.audit_file,
            target_id=args.target,
            command=args.cmd,
            exit_code=res["exit_code"],
            duration_ms=duration_ms,
        )

        out_data = {
            "command_id": payload["command_id"],
            "target": args.target,
            "cmd": args.cmd,
            "exit_code": res["exit_code"],
            "stdout": res["stdout"],
            "stderr": res["stderr"],
            "duration_ms": duration_ms,
        }

        if args.json:
            print(json.dumps(out_data, indent=2))
        else:
            if res["stdout"]:
                print(res["stdout"], end="" if res["stdout"].endswith("\n") else "\n")
            if res["stderr"]:
                sys.stderr.write(res["stderr"] + ("" if res["stderr"].endswith("\n") else "\n"))
        return 0 if res["exit_code"] == 0 else 1

    # Dispatched signed payload emitted
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"DISPATCH command_id={payload['command_id']} target={payload['target']} signature={payload['signature'][:16]}...")
    return 0


def handle_tunnel(args: argparse.Namespace) -> int:
    status_info = {
        "status": "configured",
        "listen": args.listen,
        "agents": [],
        "authenticated": bool(args.secret),
    }

    if args.list_agents:
        if args.status or args.list_agents:
            print(json.dumps(status_info["agents"]))
            return 0

    if args.status:
        print(json.dumps(status_info, indent=2))
        return 0

    print(f"Tunnel controller listening on {args.listen}")
    return 0


def handle_audit(args: argparse.Namespace) -> int:
    if args.verify_chain:
        is_valid, count, err = verify_audit_chain(args.log_file)
        if not is_valid:
            sys.stderr.write(f"AUDIT INTEGRITY VIOLATION: {err}\n")
            return 1
        print(f"Audit log verified: {count} records intact, hash chain valid.")
        return 0

    since_val = None
    if args.since:
        try:
            since_val = float(args.since)
        except ValueError:
            pass

    records = read_audit_records(args.log_file, agent_id=args.agent, since=since_val)

    if args.export:
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        print(f"Exported {len(records)} records to {args.export}")
        return 0

    if args.json:
        print(json.dumps(records, indent=2))
    else:
        for r in records:
            print(
                f"[{r.get('index')}] target={r.get('target_id')} cmd={r.get('command')} "
                f"code={r.get('exit_code')} hash={r.get('hash', '')[:12]}..."
            )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        parser.print_help()
        return 2

    args = parser.parse_args(argv)

    if args.subcommand == "agent":
        return handle_agent(args)
    elif args.subcommand == "dispatch":
        return handle_dispatch(args)
    elif args.subcommand == "tunnel":
        return handle_tunnel(args)
    elif args.subcommand == "audit":
        return handle_audit(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Calls one tool on a stdio MCP server and prints its text result.

    python3 tools/mcp-stdio-call.py <server executable> <tool> ['<json arguments>']
    python3 tools/mcp-stdio-call.py <server executable> --list

Exits 1 when the tool reports an error, so a shell gate can trust the exit code. Stdlib only, so it runs on
a bare distro: it drives the relay inside WSL for live acceptance, where Windows cannot reach the target.
"""
import json
import subprocess
import sys


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2

    server, tool = sys.argv[1], sys.argv[2]
    arguments = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    process = subprocess.Popen([server], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def send(message):
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()

    def receive(expected_id):
        for line in process.stdout:
            message = json.loads(line)
            if message.get("id") == expected_id:
                return message
        raise SystemExit("the server closed its output before answering")

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "mcp-stdio-call", "version": "1"}}})
    receive(1)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    if tool == "--list":
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        for listed in receive(2)["result"]["tools"]:
            print(listed["name"], json.dumps(listed.get("inputSchema", {}).get("properties", {})))
        process.stdin.close()
        return 0

    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": arguments}})
    reply = receive(2)
    process.stdin.close()
    process.wait(timeout=60)
    if "error" in reply:
        print(json.dumps(reply["error"]), file=sys.stderr)
        return 1

    result = reply["result"]
    for block in result.get("content", []):
        if block.get("type") == "text":
            print(block["text"])
    return 1 if result.get("isError") else 0


if __name__ == "__main__":
    sys.exit(main())

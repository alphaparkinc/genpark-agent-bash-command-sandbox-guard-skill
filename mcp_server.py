import sys, json
from client import AgentBashCommandSandboxGuard

def main():
    guard = AgentBashCommandSandboxGuard()
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try:
            req = json.loads(line)
            method = req.get("method")
            rid = req.get("id")
            params = req.get("params", {})

            if method == "tools/list":
                res = {
                    "tools": [
                        {"name": "inspect_command", "description": "Inspect shell command for destructive patterns.", "inputSchema": {"type": "object", "properties": {"cmd_string": {"type": "string"}}, "required": ["cmd_string"]}},
                        {"name": "run_benchmark_bash_guard", "description": "Run security benchmark.", "inputSchema": {"type": "object"}}
                    ]
                }
            elif method == "tools/call":
                tname = params.get("name")
                args = params.get("arguments", {})
                if tname == "inspect_command":
                    out = guard.inspect_command(args.get("cmd_string", ""))
                elif tname == "run_benchmark_bash_guard":
                    out = guard.run_benchmark_bash_guard()
                else:
                    out = {"error": f"Unknown tool {tname}"}
                res = {"content": [{"type": "text", "text": json.dumps(out)}]}
            else:
                res = {"error": "Unsupported method"}
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}), flush=True)
        except Exception as e:
            print(json.dumps({"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}}), flush=True)

if __name__ == "__main__":
    main()

from client import AgentBashCommandSandboxGuard
import json

def main():
    guard = AgentBashCommandSandboxGuard()
    res = guard.run_benchmark_bash_guard()
    print("Bash Sandbox Guard Benchmark Result:")
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()

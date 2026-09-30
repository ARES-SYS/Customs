# Customs — Dual 17-Stage Verification Gateway

Customs inspects everything that enters or leaves an AI agent system. Two independent 17-stage pipelines: one for input (files, messages, prompts) and one for output (agent responses, tool calls, decisions).

**Philosophy:** "Sovereignty Through Infrastructure." Zero Trust. Nothing enters or exits without inspection.

## Architecture

```
INPUT  → Pipeline (17 stages) → Agent
OUTPUT → Guard (17 checks)    → User
```

## Usage

```bash
# Analyze a file (full input pipeline)
python3 customs.py --file /path/to/sample

# Verify agent output (full guard)
python3 customs.py --text "agent response..."

# MCP server mode (stdio JSON-RPC)
python3 customs.py --serve

# Run demo (both pipeline + guard)
python3 customs.py --check
```

## Modules

| Module | Purpose |
|--------|---------|
| `guard/` | 17 output verification checks against agent responses |
| `pipeline/` | 17 input analysis stages for files and messages |
| `rules/` | YARA-based detection rules |
| `store/` | SQLite-backed IOC and audit persistence |

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)
- SQLite3 (built-in)

## License

MIT

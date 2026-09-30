# REASONING — Customs

## Why this exists

AI agents process untrusted input (user prompts, files, tool outputs) and produce output that goes directly to users. Most agent frameworks have no inspection layer between these boundaries. Prompt injection, data exfiltration, and hallucinated tool calls pass through unchecked.

Customs fills that gap with a dual inspection architecture: 17 stages on input, 17 checks on output. Neither side trusts the other.

## Design decisions

**Dual pipeline, not one.** Input risks (injection, malware, oversized payloads) and output risks (hallucination, PII leaks, forbidden actions) are fundamentally different. Two separate 17-stage sequences address each class independently.

**No external LLM dependency.** Rule-based, regex, and heuristic checks. Adding an LLM call would introduce the same trust problem Customs is designed to solve — who inspects the inspector?

**SQLite for persistence, not complexity.** IOCs, audit trails, and rule state live in SQLite. Portable, zero-config, no external database required. Same database works on a laptop or in CI/CD.

**MCP-compatible.** Stdio JSON-RPC server mode integrates directly with MCP hosts. Customs acts as a tool that any MCP-compatible agent can call before processing input or delivering output.

## What it doesn't do

- It doesn't replace a WAF or IDS. It sits at the agent boundary, not the network boundary.
- It doesn't modify agent behavior. It only inspects and reports.
- It doesn't require a GPU, cloud, or API key. It runs locally.

## Why public

The same inspection architecture that protects an agent from external attacks should be available to everyone building AI systems — not locked behind enterprise contracts or cloud APIs. Zero Trust at the agent boundary is infrastructure, not a product.

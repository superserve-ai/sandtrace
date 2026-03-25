# Sandtrace

Hypervisor-level audit trails for AI agent sandboxes.

Agent observability tools log what agents report doing. Sandtrace logs what they actually do.

## Quick start

```bash
sandtrace demo
sandtrace verify ./run_abc123.jsonl
```

## Architecture

Sandtrace sits beneath the agent's trust boundary — capturing network egress, filesystem changes, and system calls at the host layer via a Firecracker VM tap interface. The agent cannot see it, influence it, or suppress it.

## License

Apache 2.0

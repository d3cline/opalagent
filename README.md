# OpalAgent

Terminal-native AI operations for [Opalstack](https://opalstack.com/).

OpalAgent connects Opalstack's permanent control-plane MCP/API with optional per-OS-user VibeShell MCP endpoints. It can plan deployments, inspect infrastructure, debug logs, patch code, run commands, and manage Opalstack resources while keeping production changes behind explicit safety policy.

## Install

macOS and Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/d3cline/opalagent/main/install.sh | bash
```

Or clone and install locally:

```bash
git clone https://github.com/d3cline/opalagent.git
cd opalagent
./install.sh
```

The executable is `opalagent`.

## Requirements

- macOS or Linux
- Python 3.10+ for the source-install fallback
- an Opalstack Vibe MCP/API token
- one model provider:
  - OpenAI: `OPENAI_API_KEY`
  - Anthropic: `ANTHROPIC_API_KEY`
  - Ollama: a reachable local Ollama server, or `OLLAMA_BASE_URL` / `OLLAMA_API_KEY`

## First run

Authenticate to Opalstack:

```bash
opalagent auth login
opalagent auth mcp-status
```

Then configure one AI provider.

OpenAI:

```bash
export OPENAI_API_KEY='...'
```

Anthropic:

```bash
export ANTHROPIC_API_KEY='...'
```

Local Ollama:

```bash
ollama pull gpt-oss:20b
opalagent agent --provider ollama
```

Optional Ollama configuration:

```bash
export OLLAMA_BASE_URL='http://127.0.0.1:11434/v1'
export OLLAMA_MODEL='gpt-oss:20b'
```

If multiple providers are available, interactive sessions ask which one to use. Automation must choose explicitly with `--provider` or `OPAL_AGENT_PROVIDER`.

## Workflow modes

OpalAgent starts in **PLAN** mode.

```text
PLAN    read-only planning, discovery, architecture
BUILD   high-agency build/test/deploy work
OPS     logs, runtime diagnosis, narrow repairs
MANAGE  read-only inventory, audit, reporting
```

Inside the console:

```text
/mode plan
/mode build
/mode ops
/mode manage
/tier lean
/tier normal
/tier heavy
/execute
/status
/help
```

`/execute` moves an agreed PLAN into BUILD mode. The default tier rises with the workflow; you can override it explicitly.

## Opalstack model

OpalAgent treats Opalstack as managed hosting, not a generic VPS.

```text
Opalstack MCP/API        VibeShell MCP
(control plane)          (per-user execution plane)
      |                         |
      | domains, sites          | files, logs
      | apps, users             | patches, commands
      | DB, mail, TLS           | builds, tests
      +------------+------------+
                   |
               OpalAgent
```

The control plane is always authoritative. Managed resources must reach **READY** before dependent work continues.

For user-space work, OpalAgent resolves:

```text
domain -> site/route -> application -> OS user -> VibeShell
```

VibeShell is optional. When installed through Opalstack's application-installer system, OpalAgent waits for the managed objects to become READY, obtains the installer-created credential through the Opalstack Notice Log locally, probes the MCP endpoint, and then uses the capabilities actually advertised by VibeShell.

Direct SSH is reserved for bootstrap/recovery, not normal operation.

## Safety

The default posture is `SAFE/REVIEWED`.

- PLAN and MANAGE are hard read-only modes.
- SAFE mode blocks destructive control-plane actions.
- VibeShell deletes are converted to reversible trash moves where possible.
- Existing-file overwrites are blocked in favor of patches/backups.
- Shell execution is reviewed.
- `--autopilot` skips approvals only inside the SAFE capability set.
- `--dangerous` unlocks destructive operations but still requires explicit confirmation.
- Installer credentials and VibeShell bearer keys stay local to OpalAgent and are redacted before model context.

Use scoped Opalstack Vibe tokens for production accounts.

## Useful commands

```bash
opalagent                    # interactive agent console
opalagent agent --help
opalagent auth status
opalagent auth mcp-status
opalagent users list
opalagent apps list
opalagent sites list
opalagent domains list
opalagent --help
```

## Build a standalone binary

```bash
./build-binary.sh
./dist/opalagent --version
```

PyInstaller builds are platform-specific; build macOS binaries on macOS and Linux binaries on Linux.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev,keyring]'
pytest -q
```

## License

MIT. See [LICENSE](LICENSE).

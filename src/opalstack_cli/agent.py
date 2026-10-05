"""Conversational Opalstack agent: control plane + VibeShell + reviewed SSH.

The agent deliberately separates three authority planes:

* Opalstack MCP: account/control-plane objects (apps, users, sites, DNS, DBs, etc.)
* VibeShell MCP: files/logs and optional per-user command execution
* reviewed SSH: bootstrap/fallback runtime execution

OpenAI, Anthropic, and Ollama use the same client-side MCP bridge. OPAL owns MCP transport,
credentials, safety policy, approvals, and journaling; model providers only receive typed
function schemas. Local and MCP mutations pass through the same policy engine.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import click
import requests
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import ANSI

from . import config

OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
OPALSTACK_MCP_URL = "https://my.opalstack.com/mcp"
OLLAMA_DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"
OPENAI_MODEL_PRESETS = {
    "cheap": ("gpt-5.6-luna", "low"),
    "default": ("gpt-5.6-terra", "low"),
    "deep": ("gpt-5.6-sol", "medium"),
}

ANTHROPIC_MODEL_PRESETS = {
    "cheap": ("claude-haiku-4-5-20251001", "low"),
    "default": ("claude-sonnet-5-5", "low"),
    "deep": ("claude-opus-5-5", "medium"),
}

# Ollama model selection is intentionally dynamic because local users install different models.
# "auto" resolves to OLLAMA_MODEL[_TIER] or a locally installed model at session start.
OLLAMA_MODEL_PRESETS = {
    "cheap": ("auto", "low"),
    "default": ("auto", "medium"),
    "deep": ("auto", "high"),
}

# Backwards-compatible name used by older tests/extensions.
MODEL_PRESETS = OPENAI_MODEL_PRESETS
MODEL_PRESETS_BY_PROVIDER = {
    "openai": OPENAI_MODEL_PRESETS,
    "anthropic": ANTHROPIC_MODEL_PRESETS,
    "ollama": OLLAMA_MODEL_PRESETS,
}

# User-facing cost tiers. Workflow mode chooses a default tier; /tier can override it.
TIER_TO_PRESET = {
    "lean": "cheap",
    "normal": "default",
    "heavy": "deep",
}

WORK_MODES = {
    "plan": {
        "label": "PLAN",
        "default_tier": "normal",
        "read_only": True,
        "description": "Talk it through, inspect, design, and produce a plan. No changes.",
    },
    "build": {
        "label": "BUILD",
        "default_tier": "heavy",
        "read_only": False,
        "description": "Build, patch, test, deploy, and verify with SAFE/REVIEWED writes.",
    },
    "ops": {
        "label": "OPS",
        "default_tier": "normal",
        "read_only": False,
        "description": "Diagnose logs/runtime/infrastructure and make narrow reviewed repairs.",
    },
    "manage": {
        "label": "MANAGE",
        "default_tier": "normal",
        "read_only": True,
        "description": "Inventory, report, audit, and explain the account. No changes.",
    },
}

BANNER = r"""
    ███████                        ████    █████████                                 █████
  ███▒▒▒▒▒███                     ▒▒███   ███▒▒▒▒▒███                               ▒▒███
 ███     ▒▒███ ████████   ██████   ▒███  ▒███    ▒███   ███████  ██████  ████████   ███████
▒███      ▒███▒▒███▒▒███ ▒▒▒▒▒███  ▒███  ▒███████████  ███▒▒███ ███▒▒███▒▒███▒▒███ ▒▒▒███▒
▒███      ▒███ ▒███ ▒███  ███████  ▒███  ▒███▒▒▒▒▒███ ▒███ ▒███▒███████  ▒███ ▒███   ▒███
▒▒███     ███  ▒███ ▒███ ███▒▒███  ▒███  ▒███    ▒███ ▒███ ▒███▒███▒▒▒   ▒███ ▒███   ▒███ ███
 ▒▒▒███████▒   ▒███████ ▒▒████████ █████ █████   █████▒▒███████▒▒██████  ████ █████  ▒▒█████
   ▒▒▒▒▒▒▒     ▒███▒▒▒   ▒▒▒▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒  ▒▒▒▒▒███ ▒▒▒▒▒▒  ▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒
               ▒███                                    ███ ▒███
               █████                                  ▒▒██████
              ▒▒▒▒▒                                    ▒▒▒▒▒▒
""".strip("\n")

PLATFORM_CONTEXT = """
OPALSTACK PLATFORM MODEL — HARD CONTRACT

Opalstack is managed hosting, not a generic VPS. The classic Opalstack API/MCP is the permanent,
authoritative control plane and is always the first place to discover or change managed infrastructure.
VibeShell is a separate, optional, per-OS-user user-space MCP surface. Never confuse the two.

Managed object graph:
- SERVER hosts OS users, applications, IPs and managed services.
- OS USER is the Unix ownership/security boundary. Applications belong to an OS user and run as it.
- APPLICATION is a managed runtime/app object owned by an OS user. Application creation may use an
  Opalstack application installer via `installer_url`; installers are the preferred way to provision
  packaged software such as VibeShell. Do not reimplement an installer with ad-hoc SSH/file copying.
- DOMAIN is a DNS name. A domain is not a site and a site is not an application.
- SITE is web-server configuration: IP/server + domains + URL routes + TLS behavior.
- SITE ROUTE maps a URL path such as `/` or `/api` to an application.
- DATABASE and DATABASE USER are separate managed objects; grants connect them.
- CERTIFICATE/TLS, mail, DNS, notices and other dashboard objects belong to the control plane.
- NOTICE LOG is also an installer handoff channel. Opalstack installers commonly publish generated credentials
  and completion details there. Installer-created VibeShell bearer keys are retrieved from matching notices,
  never invented, requested from the model, or assumed to live in application JSON. The model should not read
  a secret-bearing installer notice directly; `vibeshell_adopt` performs that credential handoff locally.

Readiness law:
- Opalstack mutations are asynchronous. Accepted does not mean usable.
- Every managed dependency that exposes readiness must reach READY (`ready=true` and/or status READY)
  before the next dependent operation: wait until READY. Never race provisioning.
- Typical dependency order is: resolve/create OS user -> wait READY -> create application (using the
  correct installer when software is packaged) -> wait READY -> create/resolve domain/site/routes ->
  wait READY -> verify the public/data-plane endpoint.

VibeShell law:
- VibeShell is not globally present and is not assumed. It is an optional MCP endpoint attached to one
  OS user's environment so classic managed hosting can remain unchanged for users who do not want it.
- The normal provisioning path is: classic Opalstack MCP/API -> create/manage the VibeShell application
  with the canonical VibeShell application installer (`installer_url`) -> wait application READY ->
  create/resolve its site/route as needed -> wait site READY -> read the matching installer notice for the
  application ID/name -> adopt/probe the VibeShell endpoint -> authenticate -> tools/list -> verify filesystem
  and command capabilities.
- OPAL CLI does NOT install or patch VibeShell source over SSH. The VibeShell repository/installer is the
  source of truth. The CLI consumes the endpoint and advertised MCP capabilities after Opalstack provisions it.
- Before any file/log/code/runtime/build/test/git/command task, resolve the target domain/site/application
  through the control plane to its owning OS user, then call `vibeshell_status` for that user.
- VibeShell states are conceptually ABSENT, PROVISIONING, CONTROL_PLANE_PRESENT_UNREGISTERED,
  UNREACHABLE, AUTH_FAILED, READY_FS and READY_EXEC.
- If VibeShell is ABSENT and the requested task truly needs user-space access, provision it using the
  Opalstack application installer through the control plane, wait READY, then adopt/register the endpoint.
- READY_FS means authenticated filesystem/log MCP tools are available. READY_EXEC means VibeShell also
  advertises `shell_exec` (or legacy `shell_run`) for command execution.
- Once READY, use VibeShell for files, logs, patches and commands. SSH is bootstrap/recovery only and must
  never replace the normal installer + VibeShell lifecycle.
""".strip()


SYSTEM_PROMPT = """You are OPAL, the terminal-native Opalstack operator and coding agent.

You work across three explicit planes and must choose the narrowest correct one. Depending on
model provider, MCP tools may be surfaced natively by server label or as typed names prefixed with
`opalstack__` / `vibe_*__`; those are the same authority planes, not different systems.
1. OPALSTACK CONTROL PLANE: use the `opalstack` MCP server/tools for accounts, servers, IPs,
   shell users, applications, domains, DNS, sites/routes, TLS certificates, PostgreSQL,
   MariaDB, mailboxes/addresses, notices, tokens, and other dashboard/API objects.
2. USER-SPACE PLANE: use a configured `vibe_*` VibeShell MCP server to inspect, search,
   read, write, patch, move, delete, diff, or tail files/logs inside that OS-user boundary.
   If that endpoint exposes `shell_exec` (or legacy `shell_run`), prefer it for tests, builds, git, migrations,
   package tools, process inspection, and app scripts in the same OS-user boundary.
3. SSH BOOTSTRAP/RECOVERY PLANE: direct `ssh_exec` is not the normal operational surface. If user-space
   access is needed, first resolve/check VibeShell and make it READY. Use SSH only to bootstrap or repair
   VibeShell when that MCP surface itself is unavailable. Once VibeShell is READY_EXEC, use its advertised shell command tool there.

Platform model:
- An App is owned by an OS user. A Site maps domains to one or more app routes and TLS.
- Databases and database users are separate managed objects.
- Control-plane writes are asynchronous; discover current state first, mutate in dependency
  order, then verify readiness and data-plane behavior.
- Never invent an Opalstack resource ID, hostname, app type, route, or relationship. List/read
  the current account when needed.
- VibeShell is not the control plane. Do not use file writes to fake managed DNS/sites/apps.
- SSH is not the control plane. Do not hand-edit managed infrastructure when a typed MCP tool exists.
- OPAL SAFE mode is a hard policy boundary outside you. Never try to evade, work around, encode around,
  or replace a blocked destructive operation. A blocked delete/rebuild means stop and explain what needs human action.
- Never decide on your own to delete code/resources and "start over". Repair in place. Replacement, recreation,
  destructive migrations, arbitrary shell mutation, and permanent deletion require explicit human dangerous-mode intent.
- Prefer small, reversible changes. Preserve existing data and configuration unless the user explicitly
  asks for replacement/deletion and the policy engine permits it.
- `--autopilot` only skips review inside SAFE capabilities; it never grants destructive authority.
- After a mutation, verify the actual result rather than trusting a successful submission alone.
- OPAL intentionally exposes only a small relevant MCP tool subset to control token cost. If a needed tool is not visible,
  call `opal_tool_search` with a short capability query; matching typed tools will be exposed on the next tool turn.

VibeShell lifecycle:
For any task requiring files, logs, code, runtime state, builds, tests, git or commands, first resolve the
target through the control plane to its application and owning OS user, then call `vibeshell_status`.
If READY_FS/READY_EXEC provides the needed capability, use that VibeShell MCP surface.
If ABSENT or only present in the control plane, use the Opalstack application create/update tools with the
canonical VibeShell `installer_url`; do not SSH-copy VibeShell and do not synthesize its source. Wait for the
application to become READY, create/resolve its HTTPS site/route if necessary, wait that READY, then call
`vibeshell_adopt`. OPAL retrieves the installer-created key locally from the matching Notice Log entry keyed
to that application ID/name, verifies the endpoint, and registers the user-space MCP surface without exposing
the secret to the model. If UNREACHABLE/AUTH_FAILED, diagnose the managed
application/site/installer state first. SSH is recovery-only when the managed lifecycle itself is broken.

Interaction style:
Be concise and operator-oriented. State what changed, what was verified, and what remains. Use tools
instead of giving the user commands to run when the tool can safely do the work. Do not expose tokens,
passwords, private keys, or authorization headers in prose.
"""


def _workflow_prompt(work_mode: str, tier: str) -> str:
    mode = WORK_MODES[work_mode]
    common = (
        f"\n\nCURRENT WORKFLOW POSTURE\n"
        f"Mode: {mode['label']}\n"
        f"Cost tier: {tier.upper()}\n"
        f"Purpose: {mode['description']}\n"
    )
    if work_mode == "plan":
        return common + (
            "PLAN is strictly read-only. Inspect as needed, discuss tradeoffs, ask only necessary questions, "
            "and turn the conversation into a concrete work plan. Do not mutate infrastructure, files, or runtime state. "
            "When the plan is ready, end with a short handoff telling the human they can type /execute to run it in BUILD mode."
        )
    if work_mode == "build":
        return common + (
            "BUILD is execution-oriented. Start with a brief action plan, then make small reversible changes, test after changes, "
            "deploy in dependency order, and verify the real result. Prefer patching over replacement and stop on unexpected state."
        )
    if work_mode == "ops":
        return common + (
            "OPS is evidence-first. Inspect logs, process state, configuration, and managed resources before theorizing. "
            "Use the narrowest repair that fits the evidence, verify it, and avoid unrelated refactors or rebuilds."
        )
    return common + (
        "MANAGE is strictly read-only. Inventory, summarize, audit, explain relationships, and prioritize recommendations. "
        "Do not mutate infrastructure, files, or runtime state."
    )


class AgentError(click.ClickException):
    pass


SENSITIVE_KEYS = {"token", "password", "secret", "api_key", "authorization", "key"}


def _redact_for_journal(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            lower = str(key).lower()
            out[key] = "***" if any(part in lower for part in SENSITIVE_KEYS) else _redact_for_journal(item)
        return out
    if isinstance(value, list):
        return [_redact_for_journal(item) for item in value]
    return value


class MutationJournal:
    """Owner-only append journal for proposed/executed production mutations."""

    def __init__(self):
        base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = secrets.token_hex(4)
        self.path = base / "opalstack" / "runs" / f"{stamp}-{suffix}" / "journal.jsonl"
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

    def record(self, event: str, **payload: Any) -> None:
        item = {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **_redact_for_journal(payload),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")


class SessionTranscript:
    """Small local transcript so the CLI can reprint/save its own scrollback."""

    def __init__(self):
        self.items: list[tuple[str, str]] = []

    def add(self, role: str, text: str) -> None:
        self.items.append((role, text))

    def render(self, console: Console, limit: int = 40) -> None:
        for role, text in self.items[-max(1, limit):]:
            if role == "user":
                console.print(f"[bold magenta]you[/bold magenta]  {text}")
            elif role == "opal":
                console.print(Panel(text, title="OPAL", border_style="cyan"))
            else:
                console.print(f"[dim]{text}[/dim]")

    def save(self, path: str) -> Path:
        dest = Path(path).expanduser()
        dest.parent.mkdir(parents=True, exist_ok=True)
        body = []
        for role, text in self.items:
            body.append(f"[{role.upper()}]\n{text}\n")
        dest.write_text("\n".join(body), encoding="utf-8")
        return dest


def _shell_history_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    path = base / "opalstack" / "history"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _prompt_session() -> PromptSession:
    bindings = KeyBindings()

    @bindings.add("escape", "enter")
    def _newline(event):
        event.current_buffer.insert_text("\n")

    completer = NestedCompleter.from_nested_dict({
        "/mode": {"plan": None, "build": None, "ops": None, "manage": None},
        "/tier": {"auto": None, "lean": None, "normal": None, "heavy": None},
        "/plan": None, "/build": None, "/ops": None, "/manage": None,
        "/execute": None, "/status": None, "/help": None, "/reset": None,
        "/history": None, "/scroll": None, "/save": None, "/vibes": None,
        "/exit": None, "/quit": None,
    })
    return PromptSession(
        history=FileHistory(str(_shell_history_path())),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer,
        complete_while_typing=False,
        key_bindings=bindings,
        multiline=False,
        enable_history_search=True,
        mouse_support=False,
    )


@dataclass
class VibeEndpoint:
    label: str
    url: str
    token: str
    user: str | None = None
    app: str | None = None
    base_dir: str | None = None
    exec_enabled: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VibeEndpoint":
        return cls(
            label=str(raw.get("label", "vibe")),
            url=str(raw.get("url", "")),
            token=str(raw.get("token", "")),
            user=raw.get("user"),
            app=raw.get("app"),
            base_dir=raw.get("base_dir"),
            exec_enabled=bool(raw.get("exec_enabled", False)),
        )

    def public(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "url": self.url,
            "user": self.user,
            "app": self.app,
            "base_dir": self.base_dir,
            "exec_enabled": self.exec_enabled,
        }


def normalize_base_dir(value: str) -> str:
    value = value.strip()
    if not (value == "~" or value.startswith("~/")):
        raise AgentError("VibeShell base_dir must stay under the OS-user home (use '~' or '~/...').")
    if any(ch in value for ch in ("\x00", "\r", "\n", '"')):
        raise AgentError("VibeShell base_dir contains an unsafe character.")
    relative = value[2:] if value.startswith("~/") else ""
    if any(part == ".." for part in relative.split("/")):
        raise AgentError("VibeShell base_dir may not contain '..' path components.")
    return value


class OpenAIResponses:
    """Tiny HTTP client so the CLI does not need a second SDK dependency."""

    def __init__(self, api_key: str, timeout: float = 120.0):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

    def close(self) -> None:
        self.session.close()

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.session.post(
                OPENAI_RESPONSES_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise AgentError("Model API connection failed or timed out.") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise AgentError(f"Model API returned HTTP {response.status_code} with invalid JSON.") from exc
        if response.status_code >= 400:
            message = "Model API request failed."
            if isinstance(data, dict):
                err = data.get("error")
                if isinstance(err, dict) and isinstance(err.get("message"), str):
                    message = err["message"]
            raise AgentError(f"OpenAI HTTP {response.status_code}: {message}")
        if not isinstance(data, dict) or not isinstance(data.get("id"), str):
            raise AgentError("Model API returned an unexpected response shape.")
        return data


class AnthropicMessages:
    """Minimal Claude Messages API client; no Anthropic SDK dependency required."""

    def __init__(self, api_key: str, timeout: float = 120.0):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

    def close(self) -> None:
        self.session.close()

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.session.post(
                ANTHROPIC_MESSAGES_URL,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise AgentError("Model API connection failed or timed out.") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise AgentError(f"Model API returned HTTP {response.status_code} with invalid JSON.") from exc
        if response.status_code >= 400:
            message = "Model API request failed."
            if isinstance(data, dict):
                err = data.get("error")
                if isinstance(err, dict) and isinstance(err.get("message"), str):
                    message = err["message"]
            raise AgentError(f"Anthropic HTTP {response.status_code}: {message}")
        if not isinstance(data, dict) or not isinstance(data.get("id"), str):
            raise AgentError("Model API returned an unexpected response shape.")
        return data


class OllamaChat:
    """Minimal OpenAI-compatible Ollama chat client with function-tool support."""

    def __init__(self, base_url: str, api_key: str = "", timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key.strip()
        self.timeout = timeout
        self.session = requests.Session()

    def close(self) -> None:
        self.session.close()

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            response = self.session.post(
                f"{self.base_url}/chat/completions", headers=headers, json=payload, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise AgentError(f"Ollama connection failed at {self.base_url}.") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise AgentError(f"Ollama returned HTTP {response.status_code} with invalid JSON.") from exc
        if response.status_code >= 400:
            message = "Ollama request failed."
            if isinstance(data, dict):
                err = data.get("error")
                if isinstance(err, dict):
                    message = str(err.get("message") or message)
                elif isinstance(err, str):
                    message = err
            raise AgentError(f"Ollama HTTP {response.status_code}: {message}")
        if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
            raise AgentError("Ollama returned an unexpected response shape.")
        return data


class MCPHttpClient:
    """Small Streamable-HTTP/SSE-compatible MCP client used by the Anthropic path."""

    def __init__(self, url: str, token: str, timeout: float = 60.0):
        self.url = url
        self.token = token
        self.timeout = timeout
        self.session = requests.Session()
        self.session_id: str | None = None
        self._next_id = 1
        self.initialized = False

    def close(self) -> None:
        self.session.close()

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    @staticmethod
    def _decode_response(response: requests.Response) -> dict[str, Any]:
        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            events: list[dict[str, Any]] = []
            for line in response.text.splitlines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                raw = line[5:].strip()
                if not raw or raw == "[DONE]":
                    continue
                try:
                    value = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(value, dict):
                    events.append(value)
            if events:
                return events[-1]
            raise AgentError("MCP server returned an empty event stream.")
        try:
            value = response.json()
        except ValueError as exc:
            raise AgentError(f"MCP server returned HTTP {response.status_code} with invalid JSON.") from exc
        if not isinstance(value, dict):
            raise AgentError("MCP server returned an unexpected response shape.")
        return value

    def request(self, method: str, params: dict[str, Any] | None = None, notification: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not notification:
            payload["id"] = self._next_id
            self._next_id += 1
        if params is not None:
            payload["params"] = params
        try:
            response = self.session.post(
                self.url, headers=self._headers(), json=payload, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise AgentError(f"MCP connection failed for {self.url}") from exc
        if response.headers.get("mcp-session-id"):
            self.session_id = response.headers["mcp-session-id"]
        if notification and response.status_code in {200, 202, 204}:
            return {}
        try:
            data = self._decode_response(response)
        except AgentError:
            if response.status_code >= 400:
                raise AgentError(f"MCP HTTP {response.status_code} from {self.url}")
            raise
        if response.status_code >= 400:
            raise AgentError(f"MCP HTTP {response.status_code} from {self.url}")
        if isinstance(data.get("error"), dict):
            message = str(data["error"].get("message") or "MCP request failed")
            raise AgentError(message)
        result = data.get("result")
        if not isinstance(result, dict):
            return {"value": result}
        return result

    def initialize(self) -> None:
        if self.initialized:
            return
        self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "opalagent", "version": "0.3.0"},
            },
        )
        self.request("notifications/initialized", notification=True)
        self.initialized = True

    def list_tools(self) -> list[dict[str, Any]]:
        self.initialize()
        collected: list[dict[str, Any]] = []
        cursor: str | None = None
        seen: set[str] = set()
        while True:
            params = {"cursor": cursor} if cursor else {}
            result = self.request("tools/list", params)
            tools = result.get("tools", [])
            if isinstance(tools, list):
                collected.extend(tool for tool in tools if isinstance(tool, dict))
            next_cursor = result.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen:
                break
            seen.add(next_cursor)
            cursor = next_cursor
        return collected

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.initialize()
        return self.request("tools/call", {"name": name, "arguments": arguments})


def _agent_profile(state) -> dict[str, Any]:
    profile = state.data.setdefault("profiles", {}).setdefault(state.profile, {})
    return profile.setdefault("agent", {})


def load_vibes(state) -> list[VibeEndpoint]:
    raw = _agent_profile(state).get("vibeshells", [])
    if not isinstance(raw, list):
        return []
    out: list[VibeEndpoint] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        vibe = VibeEndpoint.from_dict(item)
        if vibe.url and vibe.token:
            out.append(vibe)
    return out


def save_vibe(state, vibe: VibeEndpoint) -> None:
    agent = _agent_profile(state)
    items = agent.setdefault("vibeshells", [])
    if not isinstance(items, list):
        items = []
        agent["vibeshells"] = items
    replacement = {
        "label": vibe.label,
        "url": vibe.url,
        "token": vibe.token,
        "user": vibe.user,
        "app": vibe.app,
        "base_dir": vibe.base_dir,
        "exec_enabled": vibe.exec_enabled,
    }
    for index, item in enumerate(items):
        if isinstance(item, dict) and item.get("label") == vibe.label:
            items[index] = replacement
            break
    else:
        items.append(replacement)
    config.save(state.data)


def remove_vibe(state, label: str) -> bool:
    agent = _agent_profile(state)
    items = agent.get("vibeshells", [])
    if not isinstance(items, list):
        return False
    kept = [item for item in items if not (isinstance(item, dict) and item.get("label") == label)]
    if len(kept) == len(items):
        return False
    agent["vibeshells"] = kept
    config.save(state.data)
    return True


def normalize_label(label: str) -> str:
    label = re.sub(r"[^A-Za-z0-9_-]+", "_", label.strip()).strip("_")
    if not label:
        raise AgentError("VibeShell label must contain letters or numbers.")
    return label[:40]


def normalize_endpoint(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise AgentError("VibeShell endpoint must be a public HTTPS URL without embedded credentials.")
    return url if url.endswith("/") else url + "/"


def _model_keys() -> dict[str, str]:
    return {
        "openai": (os.environ.get("OPAL_AGENT_API_KEY") or os.environ.get("OPENAI_API_KEY") or "").strip(),
        "anthropic": (os.environ.get("ANTHROPIC_API_KEY") or "").strip(),
        "ollama": (os.environ.get("OLLAMA_API_KEY") or "").strip(),
    }


def _ollama_base_url() -> str:
    value = (os.environ.get("OLLAMA_BASE_URL") or OLLAMA_DEFAULT_BASE_URL).strip().rstrip("/")
    if value.endswith("/api"):
        value = value[:-4] + "/v1"
    elif not value.endswith("/v1"):
        value += "/v1"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise AgentError("OLLAMA_BASE_URL must be a valid http(s) URL.")
    if parsed.scheme == "http" and (parsed.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1"}:
        raise AgentError("Remote OLLAMA_BASE_URL must use HTTPS; plain HTTP is allowed only for local Ollama.")
    return value


def _ollama_models(base_url: str | None = None, api_key: str | None = None, timeout: float = 0.35) -> list[str]:
    base = (base_url or _ollama_base_url()).rstrip("/")
    headers: dict[str, str] = {}
    key = (api_key if api_key is not None else os.environ.get("OLLAMA_API_KEY") or "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        response = requests.get(f"{base}/models", headers=headers, timeout=timeout)
        if response.status_code >= 400:
            return []
        data = response.json()
    except (requests.RequestException, ValueError):
        return []
    rows = data.get("data", []) if isinstance(data, dict) else []
    return [str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("id")]


def _ollama_available() -> bool:
    if (os.environ.get("OLLAMA_API_KEY") or "").strip():
        return True
    return bool(_ollama_models())


def _resolve_ollama_model(tier: str) -> str:
    tier_var = {"lean": "OLLAMA_MODEL_LEAN", "normal": "OLLAMA_MODEL_NORMAL", "heavy": "OLLAMA_MODEL_HEAVY"}[tier]
    explicit = (os.environ.get(tier_var) or os.environ.get("OLLAMA_MODEL") or "").strip()
    if explicit:
        return explicit
    models = _ollama_models(timeout=2.5)
    if not models:
        raise AgentError(
            "Ollama is selected but no models are available. Run `ollama pull <model>` or set OLLAMA_MODEL."
        )
    preferred = [
        "gpt-oss:20b", "qwen3:8b", "qwen3", "llama3.3", "llama3.2",
    ]
    lower = {m.lower(): m for m in models}
    for candidate in preferred:
        if candidate in lower:
            return lower[candidate]
        for model in models:
            if model.lower().startswith(candidate + ":"):
                return model
    return models[0]


def _resolve_provider(requested: str | None = None) -> tuple[str, str]:
    requested = (requested or os.environ.get("OPAL_AGENT_PROVIDER") or "auto").strip().lower()
    if requested not in {"auto", "openai", "anthropic", "ollama"}:
        raise AgentError("Model provider must be openai, anthropic, or ollama.")
    keys = _model_keys()
    if requested == "ollama":
        if not _ollama_available():
            raise AgentError(
                "Ollama selected but no Ollama server/model is reachable. Start Ollama, pull a model, "
                "or set OLLAMA_BASE_URL/OLLAMA_API_KEY."
            )
        return "ollama", keys["ollama"]
    if requested != "auto":
        if not keys[requested]:
            variable = "OPENAI_API_KEY (or OPAL_AGENT_API_KEY)" if requested == "openai" else "ANTHROPIC_API_KEY"
            raise AgentError(f"{requested.title()} selected but {variable} is not set.")
        return requested, keys[requested]

    available = [name for name in ("openai", "anthropic") if keys[name]]
    if _ollama_available():
        available.append("ollama")
    if not available:
        raise AgentError(
            "No model provider available. Set OPENAI_API_KEY or ANTHROPIC_API_KEY, or start Ollama locally."
        )
    if len(available) == 1:
        return available[0], keys[available[0]]
    if not sys.stdin.isatty():
        raise AgentError(
            "Multiple model providers are available. Choose with --provider openai|anthropic|ollama "
            "or OPAL_AGENT_PROVIDER."
        )
    choice = click.prompt(
        "Multiple model providers are available. Use",
        type=click.Choice(available, case_sensitive=False),
        default=available[0],
        show_default=True,
    ).lower()
    return choice, keys[choice]

def _model_settings(state, provider: str, model: str | None, reasoning: str | None) -> tuple[str, str]:
    saved = _agent_profile(state)
    presets = MODEL_PRESETS_BY_PROVIDER[provider]
    saved_model = saved.get(f"{provider}_model")
    if provider == "openai" and not saved_model:
        saved_model = saved.get("model")
    chosen_model = model or os.environ.get("OPAL_AGENT_MODEL") or saved_model or presets["default"][0]
    if provider == "ollama" and chosen_model == "auto":
        chosen_model = _resolve_ollama_model("normal")
    return (
        chosen_model,
        reasoning or os.environ.get("OPAL_AGENT_REASONING") or saved.get("reasoning") or presets["default"][1],
    )


def _resolve_work_mode(value: str | None) -> str:
    mode = (value or os.environ.get("OPAL_AGENT_MODE") or "plan").strip().lower()
    if mode not in WORK_MODES:
        raise AgentError("Mode must be plan, build, ops, or manage.")
    return mode


def _resolve_tier(work_mode: str, value: str | None) -> tuple[str, bool]:
    raw = (value or os.environ.get("OPAL_AGENT_TIER") or "auto").strip().lower()
    if raw == "auto":
        return WORK_MODES[work_mode]["default_tier"], False
    if raw not in TIER_TO_PRESET:
        raise AgentError("Tier must be auto, lean, normal, or heavy.")
    return raw, True


def _tier_model(provider: str, tier: str) -> tuple[str, str]:
    model, reasoning = MODEL_PRESETS_BY_PROVIDER[provider][TIER_TO_PRESET[tier]]
    if provider == "ollama" and model == "auto":
        model = _resolve_ollama_model(tier)
    return model, reasoning


def _opal_token(state) -> str:
    return config.get_token(state.profile, state.data)


READY_RESOURCE_ALIASES = {
    "osuser": "users", "user": "users", "users": "users",
    "application": "apps", "app": "apps", "apps": "apps",
    "domain": "domains", "domains": "domains",
    "site": "sites", "sites": "sites",
    "cert": "certs", "certificate": "certs", "certs": "certs",
    "psqldb": "postgres-dbs", "postgres-db": "postgres-dbs", "postgres-dbs": "postgres-dbs",
    "psqluser": "postgres-users", "postgres-user": "postgres-users", "postgres-users": "postgres-users",
    "mariadb": "mariadb-dbs", "mariadb-db": "mariadb-dbs", "mariadb-dbs": "mariadb-dbs",
    "mariauser": "mariadb-users", "mariadb-user": "mariadb-users", "mariadb-users": "mariadb-users",
    "mailuser": "mailboxes", "mailbox": "mailboxes", "mailboxes": "mailboxes",
    "address": "addresses", "addresses": "addresses",
    "dns": "dns",
}

CONTROL_TOOL_RESOURCE = {
    "mcp_opalstack_osuser": "users",
    "osuser": "users",
    "mcp_opalstack_application": "apps",
    "application": "apps",
    "app": "apps",
    "mcp_opalstack_domain": "domains",
    "domain": "domains",
    "mcp_opalstack_site": "sites",
    "site": "sites",
    "mcp_opalstack_cert": "certs",
    "cert": "certs",
    "mcp_opalstack_psqldb": "postgres-dbs",
    "psqldb": "postgres-dbs",
    "mcp_opalstack_psqluser": "postgres-users",
    "psqluser": "postgres-users",
    "mcp_opalstack_mariadb": "mariadb-dbs",
    "mariadb": "mariadb-dbs",
    "mcp_opalstack_mariauser": "mariadb-users",
    "mariauser": "mariadb-users",
    "mcp_opalstack_mailuser": "mailboxes",
    "mailuser": "mailboxes",
    "mcp_opalstack_address": "addresses",
    "address": "addresses",
    "mcp_opalstack_dns": "dns",
    "dns": "dns",
}


def _readiness(obj: Any) -> tuple[bool | None, str | None]:
    if not isinstance(obj, dict):
        return None, None
    ready = obj.get("ready")
    status = obj.get("status")
    status_text = str(status) if status is not None else None
    if ready is True:
        return True, status_text or "READY"
    if ready is False:
        return False, status_text
    if isinstance(status, str):
        normalized = status.strip().upper()
        if normalized == "READY":
            return True, status
        if normalized:
            return False, status
    return None, status_text


def _wait_ready_object(state, resource: str, ident: str, timeout: int | float | None = None) -> dict[str, Any]:
    resource = READY_RESOURCE_ALIASES.get(resource.strip().lower(), resource.strip().lower())
    if resource not in set(READY_RESOURCE_ALIASES.values()):
        raise AgentError(f"Unsupported READY resource family: {resource}")
    if not ident:
        raise AgentError("READY wait requires an exact object ID.")
    manager = state.manager(resource)
    budget = float(timeout if timeout is not None else state.wait_timeout)
    deadline = time.monotonic() + max(0.1, budget)
    last: dict[str, Any] | None = None
    while True:
        try:
            obj = manager.read(ident)
        except click.ClickException as exc:
            raise AgentError(f"Could not read {resource} object while waiting for READY: {exc.format_message()}") from exc
        if not isinstance(obj, dict):
            raise AgentError(f"Unexpected {resource} readiness response shape.")
        last = obj
        ready, status = _readiness(obj)
        if ready is True:
            return {
                "ok": True, "resource": resource, "id": ident, "ready": True,
                "status": status or "READY",
                "name": obj.get("name") or obj.get("hostname") or obj.get("source"),
            }
        if ready is None:
            # Compatibility escape hatch for resource types that predate explicit readiness fields.
            return {
                "ok": True, "resource": resource, "id": ident, "ready": None,
                "status": status, "note": "Object did not expose ready/status; treated as synchronously available.",
            }
        if time.monotonic() >= deadline:
            return {
                "ok": False, "resource": resource, "id": ident, "ready": False,
                "status": status, "error": "Timed out waiting for Opalstack object to become READY.",
            }
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))


def _uuid_strings(value: Any) -> list[str]:
    pattern = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
    found: list[str] = []
    def walk(item: Any) -> None:
        if isinstance(item, dict):
            ident = item.get("id")
            if isinstance(ident, str) and pattern.fullmatch(ident) and ident not in found:
                found.append(ident)
            for v in item.values():
                walk(v)
        elif isinstance(item, list):
            for v in item:
                walk(v)
        elif isinstance(item, str):
            text = item.strip()
            if text.startswith(("{", "[")):
                try:
                    walk(json.loads(text))
                except ValueError:
                    pass
    walk(value)
    return found


def _control_resource_for_tool(raw_name: str) -> str | None:
    name = raw_name.strip().lower()
    if name in CONTROL_TOOL_RESOURCE:
        return CONTROL_TOOL_RESOURCE[name]
    for key, resource in CONTROL_TOOL_RESOURCE.items():
        if key in name:
            return resource
    return None


def _vibe_for_user(state, user_obj: dict[str, Any]) -> VibeEndpoint | None:
    uid = str(user_obj.get("id", ""))
    uname = str(user_obj.get("name", ""))
    for vibe in load_vibes(state):
        if vibe.user and str(vibe.user) in {uid, uname}:
            return vibe
    return None


def _control_vibeshell_candidates(state, user_obj: dict[str, Any]) -> list[dict[str, Any]]:
    uid = str(user_obj.get("id", ""))
    uname = str(user_obj.get("name", ""))
    try:
        from .cli import rows
        apps = rows(state.manager("apps").list_all(embed=["osuser"]))
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for app in apps:
        if not isinstance(app, dict):
            continue
        owner = app.get("osuser")
        owner_values: set[str] = set()
        if isinstance(owner, dict):
            owner_values.update(str(owner.get(k, "")) for k in ("id", "name"))
        elif owner is not None:
            owner_values.add(str(owner))
        name = str(app.get("name", ""))
        installer_url = str(app.get("installer_url") or "")
        installer_lower = installer_url.lower()
        is_vibeshell = (
            "vibeshell" in name.lower()
            or "vibeshell" in installer_lower
            or "php_mcp" in installer_lower
        )
        if (uid in owner_values or uname in owner_values) and is_vibeshell:
            ready, status = _readiness(app)
            try:
                _vibeshell_notice_credential(state, app)
                notice_ready = True
            except AgentError:
                notice_ready = False
            out.append({
                "id": app.get("id"), "name": name, "type": app.get("type"),
                "installer_url": app.get("installer_url"),
                "ready": ready, "status": status,
                "credential_notice": notice_ready,
            })
    return out


def vibeshell_status(state, user_selector: str) -> dict[str, Any]:
    user = _resolve_user(state, user_selector)
    username = str(user.get("name", user_selector))
    uid = str(user.get("id", ""))
    vibe = _vibe_for_user(state, user)
    candidates = _control_vibeshell_candidates(state, user)
    if vibe is None:
        if candidates:
            any_pending = any(c.get("ready") is False for c in candidates)
            notice_ready = any(bool(c.get("credential_notice")) for c in candidates)
            next_step = (
                "The installer credential notice is present. Resolve/verify the READY HTTPS site route, then run vibeshell_adopt locally."
                if notice_ready and not any_pending
                else "Wait for the installer-managed VibeShell app/site to reach READY and for its installer notice, then adopt/register the endpoint locally."
            )
            return {
                "ok": True, "state": "PROVISIONING" if any_pending else "CONTROL_PLANE_PRESENT_UNREGISTERED",
                "user": username, "user_id": uid, "registered": False,
                "control_plane_candidates": candidates,
                "installer_notice_ready": notice_ready,
                "next": next_step,
            }
        return {
            "ok": True, "state": "ABSENT", "user": username, "user_id": uid,
            "registered": False, "control_plane_candidates": [],
            "next": "Provision VibeShell through the Opalstack application installer (`installer_url`), wait READY, create/resolve its site, wait for the installer Notice Log entry, then run vibeshell_adopt.",
        }
    client = MCPHttpClient(vibe.url, vibe.token, timeout=20.0)
    try:
        tools = client.list_tools()
    except AgentError as exc:
        message = exc.format_message()
        state_name = "AUTH_FAILED" if ("401" in message or "unauthorized" in message.lower()) else "UNREACHABLE"
        return {
            "ok": False, "state": state_name, "user": username, "user_id": uid,
            "registered": True, "endpoint": vibe.url, "label": vibe.label,
            "app": vibe.app, "base_dir": vibe.base_dir, "error": message,
            "next": "Repair the installer-managed VibeShell application/site through the classic control plane, wait READY, then re-adopt/probe it.",
        }
    finally:
        client.close()
    names = sorted(str(t.get("name")) for t in tools if isinstance(t, dict) and t.get("name"))
    exec_tool = 'shell_exec' if 'shell_exec' in names else ('shell_run' if 'shell_run' in names else None)
    exec_ready = exec_tool is not None
    return {
        "ok": True, "state": "READY_EXEC" if exec_ready else "READY_FS",
        "user": username, "user_id": uid, "registered": True,
        "endpoint": vibe.url, "label": vibe.label, "app": vibe.app,
        "base_dir": vibe.base_dir, "exec_enabled": exec_ready, "exec_tool": exec_tool, "tools": names,
    }


def _function_tools() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "name": "opal_tool_search",
            "description": (
                "Search OPAL's locally discovered MCP tool catalog. Use this when the exact infrastructure or "
                "VibeShell tool you need is not currently exposed. Matching tools become available on the next tool turn."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What capability/resource you need, e.g. domains, logs, postgres, apps."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                },
                "required": ["query", "limit"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "opal_wait_ready",
            "description": "Wait for an Opalstack managed object to become READY. Use after asynchronous control-plane writes when an object is a dependency.",
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {
                    "resource": {"type": "string", "description": "Resource family: users, apps, domains, sites, certs, postgres-dbs, postgres-users, mariadb-dbs, mariadb-users, mailboxes, addresses."},
                    "id": {"type": "string", "description": "Exact object UUID."},
                    "timeout": {"type": "integer", "minimum": 1, "maximum": 600}
                },
                "required": ["resource", "id", "timeout"],
                "additionalProperties": False
            }
        },
        {
            "type": "function",
            "name": "vibeshell_status",
            "description": "Resolve an Opalstack OS user through the classic control plane and check that user's optional VibeShell endpoint/key/capabilities. Call before user-space files, logs, runtime or command work.",
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {
                    "user": {"type": "string", "description": "Exact OS-user name or UUID."}
                },
                "required": ["user"],
                "additionalProperties": False
            }
        },
        {
            "type": "function",
            "name": "ssh_exec",
            "description": (
                "Bootstrap/recovery SSH for an Opalstack OS user. Normal files, logs, tests, builds, git, process inspection "
                "and app commands belong on that user's VibeShell shell command tool once VibeShell is READY_EXEC. Use SSH only "
                "to bootstrap/repair VibeShell or for explicit recovery when VibeShell cannot be made available."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {
                    "user": {"type": "string", "description": "Exact Opalstack OS-user name or ID."},
                    "command": {"type": "string", "description": "Shell script/command to run as that user."},
                    "cwd": {
                        "type": ["string", "null"],
                        "description": "Optional directory within the user's home, e.g. ~/apps/myapp.",
                    },
                    "timeout": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 600,
                        "description": "Execution timeout in seconds.",
                    },
                    "purpose": {
                        "type": "string",
                        "enum": ["bootstrap", "recovery"],
                        "description": "Why direct SSH is required instead of the normal VibeShell user plane.",
                    },
                },
                "required": ["user", "command", "cwd", "timeout", "purpose"],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "vibeshell_adopt",
            "description": (
                "Adopt an installer-managed VibeShell after the Opalstack control plane has provisioned its app/site "
                "and all dependencies are READY. OPAL reads the installer-created bearer credential locally from the "
                "matching Opalstack Notice Log entry for that application, verifies the HTTPS MCP endpoint, discovers "
                "capabilities, and registers the user-space "
                "surface without exposing the secret to the model. This does not install VibeShell source."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {
                    "user": {"type": "string", "description": "Exact Opalstack OS-user name or ID."},
                    "app": {"type": "string", "description": "Installer-managed VibeShell application name or ID."},
                    "endpoint_url": {"type": "string", "description": "Public HTTPS URL routed to the READY VibeShell application."},
                    "label": {"type": "string", "description": "Short local label for this VibeShell endpoint."},
                },
                "required": ["user", "app", "endpoint_url", "label"],
                "additionalProperties": False,
            },
        },
    ]


def _resolve_user(state, selector: str) -> dict[str, Any]:
    # Imported lazily to avoid a circular import while cli.py registers commands.
    from .cli import resolve

    return resolve(state, "users", selector, embed=("server",))


def _resolve_app(state, selector: str) -> dict[str, Any]:
    from .cli import is_uuid, resolve

    obj = resolve(state, "apps", selector, embed=("osuser",))
    if not is_uuid(selector):
        obj = state.manager("apps").read(obj[state.manager("apps").primary_key], embed=["osuser"])
    return obj


def _ssh_target(state, user_selector: str) -> tuple[dict[str, Any], str, str]:
    from .cli import resolve

    obj = _resolve_user(state, user_selector)
    server = obj.get("server")
    if not isinstance(server, dict):
        server = resolve(state, "servers", str(server))
    host = str(server.get("hostname", ""))
    username = str(obj.get("name", ""))
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or host.startswith("-"):
        raise AgentError("Invalid server hostname returned by Opalstack.")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", username):
        raise AgentError("Invalid shell username returned by Opalstack.")
    return obj, username, host


def _approve(console: Console, title: str, body: str, autopilot: bool) -> bool:
    console.print(Panel(body, title=title, border_style="yellow"))
    if autopilot:
        console.print("[yellow]AUTOPILOT[/yellow] approved")
        return True
    if not sys.stdin.isatty():
        return False
    return click.confirm("Approve?", default=False, err=False)


def ssh_exec(
    state, args: dict[str, Any], console: Console, autopilot: bool, dangerous: bool = False,
    journal: MutationJournal | None = None,
) -> dict[str, Any]:
    user = str(args.get("user", ""))
    command = str(args.get("command", ""))
    cwd = args.get("cwd")
    timeout = int(args.get("timeout", 120))
    purpose = str(args.get("purpose") or "recovery").strip().lower()
    if purpose not in {"bootstrap", "recovery"}:
        return {"ok": False, "blocked": True, "error": "Direct SSH is bootstrap/recovery only; provide purpose=bootstrap or recovery."}
    if not command.strip():
        return {"ok": False, "error": "Empty command."}
    try:
        vibe_state = vibeshell_status(state, user)
    except Exception as exc:
        vibe_state = {"state": "UNKNOWN", "error": str(exc)}
    if vibe_state.get("state") == "READY_EXEC":
        return {
            "ok": False, "blocked": True,
            "error": "VibeShell is READY_EXEC for this OS user. Use its VibeShell shell_exec/shell_run command tool; direct SSH is reserved for bootstrap/recovery when VibeShell is unavailable.",
            "vibeshell": vibe_state,
        }

    cwd_line = ""
    if cwd:
        # Validate confinement before asking the human to approve anything.
        cwd_text = str(cwd).strip()
        if "\n" in cwd_text or "\r" in cwd_text or "\x00" in cwd_text:
            return {"ok": False, "error": "Invalid cwd."}
        if cwd_text == "~":
            cwd_line = 'cd "$HOME"\n'
        elif cwd_text.startswith("~/"):
            relative = cwd_text[2:]
            if not relative or any(part == ".." for part in relative.split("/")):
                return {"ok": False, "error": "cwd must stay inside the OS-user home."}
            cwd_line = f'cd "$HOME"/{shlex.quote(relative)}\n'
        else:
            return {"ok": False, "error": "cwd must be '~' or a path beginning with '~/'."}

    reason = _shell_destruction_reason(command)
    if reason is None and not _shell_is_safe(command):
        reason = "command is outside OPAL SAFE-mode read/test/build allowlist"

    _, username, host = _ssh_target(state, user)
    shown = f"target: {username}@{host}\npurpose: {purpose}\n"
    if cwd:
        shown += f"cwd: {cwd}\n"
    shown += f"$ {command}"

    if reason:
        console.print(Panel(shown + f"\n\nreason: {reason}", title="DANGEROUS SSH command", border_style="red"))
        if journal:
            journal.record("shell_blocked_or_dangerous", user=user, command=command, cwd=cwd, reason=reason)
        if not dangerous:
            return {
                "ok": False, "blocked": True,
                "error": f"OPAL SAFE mode blocked SSH execution: {reason}. Start explicitly with --dangerous to unlock it.",
            }
        if not _dangerous_confirmation(console, "ssh_exec"):
            return {"ok": False, "approved": False, "error": "Dangerous SSH operation was not confirmed."}
    else:
        # Shell execution always receives a human review, even under --autopilot.
        if not _approve(console, "SSH command", shown, False):
            return {"ok": False, "approved": False, "error": "User rejected SSH execution."}

    if journal:
        journal.record("shell_execute", user=username, host=host, command=command, cwd=cwd, purpose=purpose, dangerous=bool(reason))

    script = "set -eu\n" + cwd_line + command + "\n"
    try:
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", f"{username}@{host}", "sh", "-s"],
            input=script,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "OpenSSH client is not installed."}
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "error": f"SSH command exceeded {timeout}s timeout.",
            "stdout": (exc.stdout or "")[-65536:] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-65536:] if isinstance(exc.stderr, str) else "",
        }
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-131072:],
        "stderr": proc.stderr[-131072:],
        "target": f"{username}@{host}",
    }


def _php_capable(app: dict[str, Any]) -> bool:
    # Current Opalstack base app types: NPF/APA are PHP; SLP/SLN are PHP symlinks.
    app_type = str(app.get("type", "")).upper()
    return app_type in {"NPF", "APA", "SLP", "SLN"} or "PHP" in app_type


def _app_user_id(app: dict[str, Any]) -> str | None:
    value = app.get("osuser")
    if isinstance(value, dict):
        value = value.get("id")
    return str(value) if value else None



def _application_json(app: dict[str, Any]) -> dict[str, Any]:
    raw = app.get("json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _vibeshell_installer_config(app: dict[str, Any]) -> dict[str, Any]:
    """Read non-secret optional VibeShell hints from application JSON.

    The canonical Opalstack VibeShell installer publishes its bearer key through
    the Notice Log. Application JSON is only a possible source for non-secret
    endpoint/base-dir hints from custom installers.
    """
    data = _application_json(app)
    nested = data.get("vibeshell") if isinstance(data.get("vibeshell"), dict) else {}
    endpoint = (
        data.get("vibeshell_endpoint") or data.get("vibeshell_url")
        or nested.get("endpoint") or nested.get("url")
    )
    base_dir = data.get("vibeshell_base_dir") or nested.get("base_dir") or "~"
    return {
        "endpoint": str(endpoint).strip() if endpoint is not None else "",
        "base_dir": str(base_dir).strip() or "~",
    }


def _notice_timestamp(notice: dict[str, Any]) -> str:
    """Best-effort sortable timestamp for notice selection."""
    for key in ("created_at", "created", "timestamp", "time", "date"):
        value = notice.get(key)
        if value is not None:
            return str(value)
    return ""


def _vibeshell_notice_credential(state, app: dict[str, Any]) -> str:
    """Find the installer-created VibeShell bearer key in the Notice Log.

    Canonical installer notices look like:
      Created MCP VibeSHEL app NAME with Application ID: UUID / Bearer key: TOKEN

    Matching is anchored to the application ID when available. The credential is
    consumed locally by OPAL and is never returned to the model.
    """
    app_id = str(app.get("id") or "").strip()
    app_name = str(app.get("name") or "").strip()
    try:
        raw_notices = state.manager("notices").list_all()
        if isinstance(raw_notices, list):
            notices = raw_notices
        elif isinstance(raw_notices, dict) and all(isinstance(v, list) for v in raw_notices.values()):
            notices = [item for values in raw_notices.values() for item in values]
        elif isinstance(raw_notices, dict):
            notices = [raw_notices]
        else:
            raise TypeError("unexpected notice response shape")
    except Exception as exc:
        raise AgentError(
            "Could not read the Opalstack Notice Log for the VibeShell installer credential."
        ) from exc

    token_re = re.compile(r"Bearer\s+(?:key|token)\s*:\s*([A-Fa-f0-9]{40,128})", re.I)
    candidates: list[tuple[int, str, int, str]] = []
    for idx, notice in enumerate(notices):
        if not isinstance(notice, dict):
            continue
        content = str(notice.get("content") or "")
        lower = content.lower()
        if "vibeshel" not in lower and "vibeshell" not in lower:
            continue
        match = token_re.search(content)
        if not match:
            continue
        score = 0
        if app_id and re.search(
            rf"Application\s+ID\s*:\s*{re.escape(app_id)}(?:\b|\s|/|$)", content, re.I
        ):
            score = 100
        elif app_name and re.search(rf"\bapp\s+{re.escape(app_name)}\b", content, re.I):
            score = 50
        if score:
            candidates.append((score, _notice_timestamp(notice), -idx, match.group(1)))

    if not candidates:
        raise AgentError(
            "No installer-created VibeShell bearer credential was found in the Opalstack Notice Log "
            f"for application {app_name or app_id or 'unknown'}. Wait for the installer notice, then retry adoption."
        )

    # Prefer exact app-ID matches, then newest timestamp when available, then
    # the API's existing result order as a deterministic fallback.
    candidates.sort(reverse=True)
    return candidates[0][3]

def vibeshell_adopt(state, args: dict[str, Any]) -> dict[str, Any]:
    """Register a READY installer-managed VibeShell without giving its secret to the model."""
    user_selector = str(args.get("user", "")).strip()
    app_selector = str(args.get("app", "")).strip()
    endpoint_arg = str(args.get("endpoint_url", "")).strip()
    label = normalize_label(str(args.get("label", "")).strip())

    user = _resolve_user(state, user_selector)
    if user.get("id"):
        waited = _wait_ready_object(state, "users", str(user["id"]), min(int(state.wait_timeout), 600))
        if waited.get("ready") is False:
            raise AgentError("OS user did not become READY; VibeShell adoption stopped.")
        user = _resolve_user(state, user_selector)

    app = _resolve_app(state, app_selector)
    if app.get("id"):
        waited = _wait_ready_object(state, "apps", str(app["id"]), min(int(state.wait_timeout), 600))
        if waited.get("ready") is False:
            raise AgentError("VibeShell application did not become READY; adoption stopped.")
        app = _resolve_app(state, app_selector)

    app_user = _app_user_id(app)
    if app_user and str(user.get("id", "")) != app_user:
        raise AgentError("Selected VibeShell application belongs to a different Opalstack OS user.")

    cfg = _vibeshell_installer_config(app)
    token = _vibeshell_notice_credential(state, app)
    if len(token) < 20 or any(ch in token for ch in "\r\n\x00"):
        raise AgentError("The installer-created VibeShell credential is invalid.")

    endpoint = normalize_endpoint(endpoint_arg or cfg["endpoint"])
    base_dir = normalize_base_dir(cfg["base_dir"])

    client = MCPHttpClient(endpoint, token, timeout=20.0)
    try:
        tools = client.list_tools()
    finally:
        client.close()
    names = sorted(str(t.get("name")) for t in tools if isinstance(t, dict) and t.get("name"))
    required = {"fs_info", "fs_read", "fs_write", "fs_search"}
    missing = sorted(required.difference(names))
    if missing:
        raise AgentError("VibeShell endpoint is reachable but missing expected tools: " + ", ".join(missing))
    exec_tool = "shell_exec" if "shell_exec" in names else ("shell_run" if "shell_run" in names else None)

    endpoint_obj = VibeEndpoint(
        label=label,
        url=endpoint,
        token=token,
        user=str(user.get("name") or user.get("id") or user_selector),
        app=str(app.get("name") or app.get("id") or app_selector),
        base_dir=base_dir,
        exec_enabled=bool(exec_tool),
    )
    save_vibe(state, endpoint_obj)
    return {
        "ok": True,
        "state": "READY_EXEC" if exec_tool else "READY_FS",
        "registered": endpoint_obj.public(),
        "tools": names,
        "exec_tool": exec_tool,
        "note": "Installer-created bearer credential was read from the Opalstack Notice Log and stored locally; it was not exposed to the model.",
    }


def _execute_function(
    state, item: dict[str, Any], console: Console, autopilot: bool, dangerous: bool = False,
    journal: MutationJournal | None = None,
) -> dict[str, Any]:
    name = item.get("name")
    try:
        arguments = json.loads(item.get("arguments") or "{}")
    except ValueError:
        return {"ok": False, "error": "Model supplied invalid JSON arguments."}
    if not isinstance(arguments, dict):
        return {"ok": False, "error": "Tool arguments must be an object."}
    try:
        if name == "opal_wait_ready":
            return _wait_ready_object(
                state, str(arguments.get("resource", "")), str(arguments.get("id", "")),
                int(arguments.get("timeout", min(int(state.wait_timeout), 600))),
            )
        if name == "vibeshell_status":
            return vibeshell_status(state, str(arguments.get("user", "")))
        if name == "ssh_exec":
            return ssh_exec(state, arguments, console, autopilot, dangerous, journal)
        if name == "vibeshell_adopt":
            result = vibeshell_adopt(state, arguments)
            if journal:
                journal.record("local_config_result", tool="vibeshell_adopt", arguments={k: v for k, v in arguments.items() if k != "token"}, result=result)
            return result
        return {"ok": False, "error": f"Unknown local function: {name}"}
    except click.ClickException as exc:
        return {"ok": False, "error": exc.format_message()}
    except Exception as exc:  # Keep local failures contained and model-readable without a traceback.
        return {"ok": False, "error": f"Local tool failed: {type(exc).__name__}"}


def _message_text(response: dict[str, Any]) -> str:
    texts: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str):
                    texts.append(text)
    return "\n".join(texts).strip()


def _usage(response: dict[str, Any]) -> tuple[int, int]:
    raw = response.get("usage")
    if not isinstance(raw, dict):
        return 0, 0
    return int(raw.get("input_tokens") or 0), int(raw.get("output_tokens") or 0)


def _cached_usage(response: dict[str, Any]) -> int:
    raw = response.get("usage")
    if not isinstance(raw, dict):
        return 0
    details = raw.get("input_tokens_details")
    if not isinstance(details, dict):
        return 0
    return int(details.get("cached_tokens") or 0)


def _anthropic_message_text(response: dict[str, Any]) -> str:
    texts: list[str] = []
    for block in response.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            texts.append(block["text"])
    return "\n".join(texts).strip()


def _anthropic_usage(response: dict[str, Any]) -> tuple[int, int]:
    raw = response.get("usage")
    if not isinstance(raw, dict):
        return 0, 0
    return int(raw.get("input_tokens") or 0), int(raw.get("output_tokens") or 0)


def _anthropic_local_tools() -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    for tool in _function_tools():
        tools.append(
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "input_schema": tool["parameters"],
                "strict": True,
            }
        )
    return tools


def _try_opal_token(state) -> str | None:
    try:
        return _opal_token(state)
    except click.ClickException:
        return None


def _mcp_server_specs(state) -> list[dict[str, str]]:
    specs: list[dict[str, str]] = []
    opal_token = _try_opal_token(state)
    if opal_token:
        specs.append(
            {
                "label": "opalstack",
                "url": OPALSTACK_MCP_URL,
                "token": opal_token,
                "description": "Official Opalstack Vibe control-plane MCP for dashboard/API resources.",
            }
        )
    labels = {"opalstack"}
    for vibe in load_vibes(state):
        label = "vibe_" + normalize_label(vibe.label).lower()
        base = label
        n = 2
        while label in labels:
            label = f"{base}_{n}"
            n += 1
        labels.add(label)
        specs.append(
            {
                "label": label,
                "url": vibe.url,
                "token": vibe.token,
                "description": (
                    f"VibeShell user-space MCP for Opalstack user {vibe.user or 'unknown'}; "
                    f"base {vibe.base_dir or 'configured server base'}."
                ),
            }
        )
    return specs


def _mcp_tool_name(server_label: str, tool_name: str) -> str:
    raw = re.sub(r"[^A-Za-z0-9_-]+", "_", f"{server_label}__{tool_name}").strip("_")
    if len(raw) <= 64:
        return raw
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]
    return f"{raw[:55]}_{digest}"


# Backwards-compatible name used by 0.2.1 tests/extensions.
_anthropic_tool_name = _mcp_tool_name


def _mcp_call_is_read_only(server_label: str, tool: dict[str, Any], arguments: dict[str, Any]) -> bool:
    annotations = tool.get("annotations")
    if isinstance(annotations, dict) and annotations.get("readOnlyHint") is True:
        return True
    name = str(tool.get("name", "")).lower()
    action = str(arguments.get("action") or arguments.get("operation") or arguments.get("method") or "").lower()
    if action in {"list", "read", "get", "search", "info", "show", "status", "inspect", "describe"}:
        return True
    if server_label.startswith("vibe_") and name in {
        "fs_info", "fs_list", "fs_read", "fs_read_lines", "fs_tail", "fs_search", "fs_diff"
    }:
        return True
    if server_label.startswith("vibe_") and name == "fs_patch" and arguments.get("dry_run") is True:
        return True
    return name.startswith(("list_", "read_", "get_", "search_", "show_", "describe_", "inspect_"))


DESTRUCTIVE_ACTIONS = {
    "delete", "destroy", "drop", "purge", "erase", "remove", "wipe", "reset", "recreate", "rebuild"
}
DESTRUCTIVE_TOOL_RE = re.compile(r"(?:^|[_-])(delete|destroy|drop|purge|erase|remove|wipe)(?:$|[_-])", re.I)
DESTRUCTIVE_SHELL_PATTERNS = [
    (re.compile(r"(^|[;&|]\s*)rm\s+.*(?:-[^\n]*r|--recursive)", re.I), "recursive rm"),
    (re.compile(r"\bfind\b[^\n]*\s-delete\b", re.I), "find -delete"),
    (re.compile(r"\bgit\s+clean\b", re.I), "git clean"),
    (re.compile(r"\bgit\s+reset\s+--hard\b", re.I), "git reset --hard"),
    (re.compile(r"\brsync\b[^\n]*\s--delete\b", re.I), "rsync --delete"),
    (re.compile(r"\b(?:shred|wipefs|mkfs(?:\.[A-Za-z0-9]+)?)\b", re.I), "filesystem destruction"),
    (re.compile(r"\bdd\b[^\n]*\bof=", re.I), "raw overwrite with dd"),
    (re.compile(r"\b(?:DROP\s+(?:DATABASE|SCHEMA|TABLE)|TRUNCATE\s+TABLE)\b", re.I), "destructive SQL"),
    (re.compile(r"\b(?:shutil\.rmtree|os\.remove|os\.unlink|Path\([^\n]*\)\.unlink)\b", re.I), "programmatic deletion"),
]


def _shell_destruction_reason(command: str) -> str | None:
    for pattern, reason in DESTRUCTIVE_SHELL_PATTERNS:
        if pattern.search(command):
            return reason
    return None


def _shell_is_observational(command: str) -> bool:
    """Read-only shell subset used by PLAN and MANAGE."""
    text = command.strip()
    if not text or any(token in text for token in (">", "`")) or "$(" in text:
        return False
    segments = [part.strip() for part in re.split(r"(?:&&|\|\||;|\n)", text) if part.strip()]
    safe = re.compile(
        r"^(?:"
        r"pwd|ls(?:\s|$)|stat(?:\s|$)|file(?:\s|$)|du(?:\s|$)|df(?:\s|$)|"
        r"cat(?:\s|$)|head(?:\s|$)|tail(?:\s|$)|wc(?:\s|$)|grep(?:\s|$)|rg(?:\s|$)|"
        r"find(?:\s|$)|ps(?:\s|$)|pgrep(?:\s|$)|"
        r"git\s+(?:status|diff|log|show|rev-parse)(?:\s|$)"
        r")",
        re.I,
    )
    return bool(segments) and all(safe.search(segment) for segment in segments)


def _shell_is_safe(command: str) -> bool:
    """Conservative SAFE-mode shell allowlist: observation, tests, and builds only."""
    text = command.strip()
    if not text or any(token in text for token in (">", "`")) or "$(" in text:
        return False
    segments = [part.strip() for part in re.split(r"(?:&&|\|\||;|\n)", text) if part.strip()]
    safe = re.compile(
        r"^(?:"
        r"pwd|ls(?:\s|$)|stat(?:\s|$)|file(?:\s|$)|du(?:\s|$)|df(?:\s|$)|"
        r"cat(?:\s|$)|head(?:\s|$)|tail(?:\s|$)|wc(?:\s|$)|grep(?:\s|$)|rg(?:\s|$)|"
        r"find(?:\s|$)|ps(?:\s|$)|pgrep(?:\s|$)|"
        r"git\s+(?:status|diff|log|show|rev-parse)(?:\s|$)|"
        r"pytest(?:\s|$)|python(?:3)?\s+-m\s+pytest(?:\s|$)|php\s+-l(?:\s|$)|"
        r"npm\s+(?:test|run\s+(?:test|build|lint))(?:\s|$)|"
        r"pnpm\s+(?:test|run\s+(?:test|build|lint))(?:\s|$)|"
        r"yarn\s+(?:test|run\s+(?:test|build|lint))(?:\s|$)|"
        r"composer\s+(?:test|check)(?:\s|$)|make\s+(?:test|check|build)(?:\s|$)|"
        r"cargo\s+(?:test|check|build)(?:\s|$)|go\s+(?:test|build)(?:\s|$)"
        r")",
        re.I,
    )
    return bool(segments) and all(safe.search(segment) for segment in segments)


def _destructive_mcp_reason(server_label: str, tool: dict[str, Any], arguments: dict[str, Any]) -> str | None:
    annotations = tool.get("annotations")
    if isinstance(annotations, dict) and annotations.get("destructiveHint") is True:
        return "MCP tool is annotated as destructive"
    name = str(tool.get("name", ""))
    action = str(arguments.get("action") or arguments.get("operation") or arguments.get("method") or "").lower()
    if action in DESTRUCTIVE_ACTIONS:
        return f"destructive action '{action}'"
    lower_name = name.lower()
    if server_label == "opalstack" and action not in {"", "list", "read", "get", "search", "info", "show", "status", "inspect", "describe"}:
        if "token" in lower_name or "account" in lower_name:
            return "credential/account mutation is outside SAFE mode"
    if server_label.startswith("vibe_") and lower_name == "fs_move" and arguments.get("overwrite") is True:
        return "fs_move overwrite=true can replace an existing destination"
    if server_label.startswith("vibe_") and lower_name == "fs_patch":
        patches = arguments.get("patches")
        if isinstance(patches, list):
            for patch in patches:
                if not isinstance(patch, dict):
                    continue
                op = str(patch.get("op", "")).lower()
                if op == "delete":
                    return "fs_patch contains an explicit line-delete operation"
                if op == "replace" and patch.get("content") == "":
                    return "fs_patch replaces a line range with empty content"
    if DESTRUCTIVE_TOOL_RE.search(name):
        return f"destructive tool '{name}'"
    if name in {"shell_exec", "shell_run"}:
        command = str(arguments.get("command", ""))
        reason = _shell_destruction_reason(command)
        if reason:
            return reason
        if not _shell_is_safe(command):
            return "shell command is outside OPAL SAFE-mode read/test/build allowlist"
    return None


def _dangerous_confirmation(console: Console, label: str) -> bool:
    phrase = f"DANGEROUS {label}"
    console.print(f"[bold red]DANGEROUS MODE[/bold red] Type exactly: [bold]{phrase}[/bold]")
    if not sys.stdin.isatty():
        return False
    return click.prompt("Confirm", default="", show_default=False) == phrase


def _redact_notice_result(value: Any) -> Any:
    """Redact common notice-log credentials before any notice result reaches an LLM."""
    if isinstance(value, dict):
        return {k: _redact_notice_result(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_notice_result(v) for v in value]
    if isinstance(value, str):
        text = value
        patterns = [
            r"(?i)(Bearer\s+(?:key|token)\s*:\s*)[^\s/]+",
            r"(?i)((?:initial\s+)?password\s*[:=]\s*)[^\s/]+",
            r"(?i)(api[_ -]?key\s*[:=]\s*)[^\s/]+",
            r"(?i)(secret\s*[:=]\s*)[^\s/]+",
        ]
        for pattern in patterns:
            text = re.sub(pattern, r"\1[REDACTED]", text)
        return text
    return value


class LocalMCPBridge:
    """Provider-neutral MCP transport, policy gate, and journal owned by OPAL."""

    def __init__(self, state, console: Console, autopilot: bool = False, dangerous: bool = False,
                 journal: MutationJournal | None = None, work_mode: str = "plan"):
        self.state = state
        self.console = console
        self.autopilot = autopilot
        self.dangerous = dangerous
        self.work_mode = _resolve_work_mode(work_mode)
        self.journal = journal or MutationJournal()
        self.clients: list[MCPHttpClient] = []
        self.runtime: dict[str, tuple[str, MCPHttpClient, dict[str, Any]]] = {}
        self.raw_runtime: dict[tuple[str, str], tuple[MCPHttpClient, dict[str, Any]]] = {}
        self.definitions: list[dict[str, Any]] = []
        self._discover()

    def _discover(self) -> None:
        for spec in _mcp_server_specs(self.state):
            client = MCPHttpClient(spec["url"], spec["token"])
            self.clients.append(client)
            try:
                tools = client.list_tools()
            except AgentError as exc:
                client.close()
                if spec["label"] == "opalstack":
                    raise AgentError(
                        "Could not initialize Opalstack Vibe MCP locally. The REST token may be valid, "
                        f"but MCP discovery failed: {exc.format_message()}"
                    ) from exc
                self.console.print(f"[yellow]warning:[/yellow] could not load {spec['label']} MCP tools")
                continue
            for definition in tools:
                raw_name = definition.get("name")
                if not isinstance(raw_name, str) or not raw_name:
                    continue
                exposed = _mcp_tool_name(spec["label"], raw_name)
                schema = definition.get("inputSchema")
                if not isinstance(schema, dict):
                    schema = {"type": "object", "properties": {}}
                desc = str(definition.get("description", ""))
                self.definitions.append({
                    "name": exposed,
                    "description": f"{spec['description']} Tool: {raw_name}. {desc}",
                    "schema": schema,
                })
                self.runtime[exposed] = (spec["label"], client, definition)
                self.raw_runtime[(spec["label"], raw_name)] = (client, definition)

    def close(self) -> None:
        for client in self.clients:
            client.close()

    def refresh(self) -> None:
        """Re-discover control/user-plane MCP surfaces after VibeShell lifecycle changes."""
        self.close()
        self.clients = []
        self.runtime = {}
        self.raw_runtime = {}
        self.definitions = []
        self._discover()

    def search_tool_names(self, query: str, limit: int = 8) -> list[str]:
        """Cheap local routing with Opalstack topology awareness."""
        q = query.lower()
        words = [w for w in re.findall(r"[a-z0-9_]+", q) if len(w) > 2]
        # Expand user language into the actual two-surface hosting model. This avoids making
        # the LLM rediscover that logs/code/runtime live behind an app's owning OS user.
        expansions: list[str] = []
        if any(w in q for w in ("log", "file", "code", "runtime", "process", "command", "shell", "build", "test", "deploy", "debug", "500")):
            expansions += ["application", "osuser", "site", "vibeshell", "fs_read", "fs_search", "fs_tail", "shell_exec", "shell_run"]
        if any(w in q for w in ("domain", "dns", "url", "website", "site", "route", "https", "ssl", "tls")):
            expansions += ["domain", "dns", "site", "application", "cert"]
        if any(w in q for w in ("postgres", "database", "db", "maria", "mysql")):
            expansions += ["psql", "maria", "database", "osuser", "application"]
        words.extend(expansions)
        scored: list[tuple[int, str]] = []
        for item in self.definitions:
            hay = f"{item['name']} {item['description']}".lower()
            score = 0
            for word in words:
                if word in item["name"].lower():
                    score += 8
                elif word in hay:
                    score += 2
            # For user-space work, prefer a registered VibeShell over SSH-like fallbacks.
            if expansions and item["name"].startswith("vibe_"):
                score += 3
            if score:
                scored.append((score, item["name"]))
        scored.sort(key=lambda x: (-x[0], x[1]))
        return [name for _, name in scored[:max(1, min(limit, 20))]]

    def catalog(self, names: list[str]) -> list[dict[str, str]]:
        wanted = set(names)
        return [
            {"name": item["name"], "description": item["description"][:320]}
            for item in self.definitions if item["name"] in wanted
        ]

    def openai_tools(self, active: set[str] | None = None) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "name": item["name"],
                "description": item["description"],
                "parameters": item["schema"],
            }
            for item in self.definitions
            if active is None or item["name"] in active
        ]

    def anthropic_tools(self, active: set[str] | None = None) -> list[dict[str, Any]]:
        return [
            {
                "name": item["name"],
                "description": item["description"],
                "input_schema": item["schema"],
            }
            for item in self.definitions
            if active is None or item["name"] in active
        ]

    def _vibe_overwrite_reason(
        self, server_label: str, client: MCPHttpClient, definition: dict[str, Any], arguments: dict[str, Any]
    ) -> str | None:
        raw_name = str(definition.get("name", ""))
        if not server_label.startswith("vibe_") or raw_name != "fs_write":
            return None
        if str(arguments.get("mode", "overwrite")).lower() == "append":
            return None
        path = arguments.get("path")
        if not isinstance(path, str) or not path or (server_label, "fs_read") not in self.raw_runtime:
            return None
        snap_client, _ = self.raw_runtime[(server_label, "fs_read")]
        try:
            result = snap_client.call_tool("fs_read", {"path": path})
        except AgentError:
            return None
        if isinstance(result, dict) and result.get("isError") is True:
            return None
        self.journal.record("before_snapshot", server=server_label, tool=raw_name, target=path, result=result)
        return "fs_write would overwrite an existing file; SAFE mode requires fs_patch or a new path"

    def _safe_trash_delete(
        self, server_label: str, arguments: dict[str, Any]
    ) -> tuple[dict[str, Any], bool] | None:
        if not server_label.startswith("vibe_") or self.dangerous:
            return None
        path = arguments.get("path")
        if not isinstance(path, str) or not path.strip():
            return {"ok": False, "blocked": True, "error": "SAFE delete requires a concrete path."}, True
        move_runtime = self.raw_runtime.get((server_label, "fs_move"))
        if move_runtime is None:
            return {
                "ok": False,
                "blocked": True,
                "error": "SAFE mode will not permanently delete this path and this VibeShell has no fs_move trash primitive.",
            }, True
        cleaned = path.strip().replace("\\", "/")
        if cleaned.startswith("~/"):
            cleaned = cleaned[2:]
        cleaned = cleaned.lstrip("/") or "root"
        cleaned = "/".join(part for part in cleaned.split("/") if part not in {"", ".", ".."})
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        destination = f".opal-trash/{stamp}/{cleaned}"
        pretty = json.dumps(
            {"requested_delete": path, "safe_action": "move-to-trash", "trash_path": destination},
            indent=2,
            ensure_ascii=False,
        )
        # Even --autopilot must not silently remove a live path from service.
        if not _approve(self.console, f"SAFE trash · {server_label}.fs_delete", pretty, False):
            self.journal.record("rejected", server=server_label, tool="fs_delete", arguments=arguments)
            return {"ok": False, "approved": False, "error": "User rejected SAFE trash move."}, True
        move_client, _ = move_runtime
        move_args = {"from": path, "to": destination, "overwrite": False, "mkdirs": True}
        self.journal.record(
            "trash_move_proposed", server=server_label, requested_tool="fs_delete",
            requested_arguments=arguments, move_arguments=move_args,
        )
        self.console.print(f"[dim]→ {server_label}.fs_move (SAFE trash)[/dim]")
        try:
            result = move_client.call_tool("fs_move", move_args)
        except click.ClickException as exc:
            self.journal.record("trash_move_failed", server=server_label, error=exc.format_message())
            return {"ok": False, "error": exc.format_message()}, True
        is_error = bool(result.get("isError", False)) if isinstance(result, dict) else False
        self.journal.record("trash_move_result", server=server_label, trash_path=destination,
                            result=result, is_error=is_error)
        if isinstance(result, dict):
            result = dict(result)
            result["opal_safety"] = {
                "permanent_delete": False,
                "translated_to": "fs_move",
                "trash_path": destination,
            }
        return result, is_error

    def _snapshot_before(self, server_label: str, client: MCPHttpClient, definition: dict[str, Any],
                         arguments: dict[str, Any]) -> None:
        raw_name = str(definition.get("name", ""))
        try:
            if server_label.startswith("vibe_") and raw_name in {"fs_write", "fs_patch", "fs_delete", "fs_move"}:
                path = arguments.get("path")
                if raw_name == "fs_move":
                    path = arguments.get("source") or arguments.get("src") or arguments.get("from")
                if isinstance(path, str) and (server_label, "fs_read") in self.raw_runtime:
                    snap_client, _ = self.raw_runtime[(server_label, "fs_read")]
                    result = snap_client.call_tool("fs_read", {"path": path})
                    self.journal.record("before_snapshot", server=server_label, tool=raw_name, target=path, result=result)
            elif server_label == "opalstack" and str(arguments.get("action", "")).lower() in {"update", "delete"}:
                ident = arguments.get("id") or arguments.get("key")
                if ident:
                    snap_args = {"action": "read", "id": ident}
                    try:
                        result = client.call_tool(raw_name, snap_args)
                    except AgentError:
                        return
                    self.journal.record("before_snapshot", server=server_label, tool=raw_name,
                                        target=str(ident), result=result)
        except Exception:
            # Snapshotting is best-effort and may never turn a safe call into an unsafe one.
            self.journal.record("snapshot_failed", server=server_label, tool=raw_name)

    def _wait_after_control_mutation(
        self, raw_name: str, arguments: dict[str, Any], result: Any
    ) -> list[dict[str, Any]]:
        resource = _control_resource_for_tool(raw_name)
        if resource is None:
            return []
        action = str(arguments.get("action") or arguments.get("operation") or arguments.get("method") or "").lower()
        if action in {"delete", "remove", "destroy"}:
            return []
        ids: list[str] = []
        explicit = arguments.get("id") or arguments.get("uuid")
        if isinstance(explicit, str) and explicit:
            ids.append(explicit)
        if not ids:
            ids.extend(_uuid_strings(result)[:8])
        waits: list[dict[str, Any]] = []
        for ident in ids:
            self.console.print(f"[dim]… waiting {resource} {ident} → READY[/dim]")
            ready = _wait_ready_object(self.state, resource, ident, min(int(getattr(self.state, "wait_timeout", 300)), 600))
            waits.append(ready)
            if ready.get("ready") is False:
                break
        return waits

    def execute(self, exposed_name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        runtime = self.runtime.get(exposed_name)
        if runtime is None:
            return {"ok": False, "error": f"Unknown MCP tool: {exposed_name}"}, True
        server_label, client, definition = runtime
        raw_name = str(definition.get("name", exposed_name))
        arguments = dict(arguments)
        if server_label.startswith("vibe_") and raw_name == "fs_patch" and arguments.get("dry_run") is not True:
            # VibeShell supports a .bak before patching. SAFE mode always asks for one.
            arguments["backup"] = True
        if raw_name == "fs_delete":
            translated = self._safe_trash_delete(server_label, arguments)
            if translated is not None:
                return translated
        read_only = _mcp_call_is_read_only(server_label, definition, arguments)
        if WORK_MODES[self.work_mode]["read_only"] and not read_only:
            self.journal.record("mode_blocked", mode=self.work_mode, server=server_label, tool=raw_name, arguments=arguments)
            return {
                "ok": False,
                "blocked": True,
                "error": (
                    f"{WORK_MODES[self.work_mode]['label']} mode is read-only. "
                    "Switch to BUILD for project changes or OPS for operational repairs."
                ),
            }, True
        destructive_reason = _destructive_mcp_reason(server_label, definition, arguments)
        if destructive_reason is None:
            destructive_reason = self._vibe_overwrite_reason(server_label, client, definition, arguments)

        if destructive_reason:
            self.journal.record("blocked_or_dangerous", server=server_label, tool=raw_name,
                                reason=destructive_reason, arguments=arguments)
            if not self.dangerous:
                return {
                    "ok": False,
                    "blocked": True,
                    "error": (
                        f"OPAL SAFE mode blocked {server_label}.{raw_name}: {destructive_reason}. "
                        "Destructive capability is unavailable unless the human explicitly starts --dangerous."
                    ),
                }, True
            if not _dangerous_confirmation(self.console, f"{server_label}.{raw_name}"):
                return {"ok": False, "approved": False, "error": "Dangerous operation was not confirmed."}, True
        elif not read_only:
            pretty = json.dumps(arguments, indent=2, ensure_ascii=False)
            force_review = server_label.startswith("vibe_") and raw_name in {"fs_move", "shell_exec", "shell_run"}
            if not _approve(self.console, f"MCP · {server_label}.{raw_name}", pretty, False if force_review else self.autopilot):
                self.journal.record("rejected", server=server_label, tool=raw_name, arguments=arguments)
                return {"ok": False, "approved": False, "error": "User rejected MCP execution."}, True

        if not read_only:
            self._snapshot_before(server_label, client, definition, arguments)
            self.journal.record("mutation_proposed", server=server_label, tool=raw_name, arguments=arguments)
        self.console.print(f"[dim]→ {server_label}.{raw_name}[/dim]")
        try:
            result = client.call_tool(raw_name, arguments)
            if server_label == "opalstack" and "notice" in raw_name.lower():
                result = _redact_notice_result(result)
        except click.ClickException as exc:
            if not read_only:
                self.journal.record("mutation_failed", server=server_label, tool=raw_name,
                                    arguments=arguments, error=exc.format_message())
            return {"ok": False, "error": exc.format_message()}, True
        is_error = bool(result.get("isError", False)) if isinstance(result, dict) else False
        readiness: list[dict[str, Any]] = []
        if not read_only and not is_error and server_label == "opalstack":
            try:
                readiness = self._wait_after_control_mutation(raw_name, arguments, result)
            except click.ClickException as exc:
                readiness = [{"ok": False, "ready": False, "error": exc.format_message()}]
            if readiness and any(item.get("ready") is False for item in readiness):
                is_error = True
            if isinstance(result, dict) and readiness:
                result = dict(result)
                result["opal_readiness"] = readiness
        if not read_only:
            self.journal.record("mutation_result", server=server_label, tool=raw_name,
                                arguments=arguments, result=result, is_error=is_error, readiness=readiness)
        return result, is_error


def _openai_chat_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tool in tools:
        if tool.get("type") != "function":
            continue
        fn = {
            "name": tool.get("name"),
            "description": tool.get("description", ""),
            "parameters": tool.get("parameters", {"type": "object", "properties": {}}),
        }
        out.append({"type": "function", "function": fn})
    return out


def _chat_usage(response: dict[str, Any]) -> tuple[int, int]:
    usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
    return int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)


class OpenAIAgentSession:
    provider = "openai"

    def __init__(
        self,
        state,
        api_key: str,
        model: str | None = None,
        reasoning: str | None = None,
        autopilot: bool = False,
        max_output_tokens: int = 4096,
        console: Console | None = None,
        dangerous: bool = False,
        work_mode: str | None = None,
        tier: str | None = None,
    ):
        self.state = state
        self.work_mode = _resolve_work_mode(work_mode)
        self.tier, self.tier_locked = _resolve_tier(self.work_mode, tier)
        default_model, default_reasoning = _tier_model(self.provider, self.tier)
        self.model_override = model is not None or bool(os.environ.get("OPAL_AGENT_MODEL"))
        self.reasoning_override = reasoning is not None or bool(os.environ.get("OPAL_AGENT_REASONING"))
        self.tier_locked = self.tier_locked or self.model_override or self.reasoning_override
        self.model, self.reasoning = _model_settings(
            state, self.provider, model or (None if self.model_override else default_model),
            reasoning or (None if self.reasoning_override else default_reasoning),
        )
        self.autopilot = autopilot
        self.dangerous = dangerous
        self.max_output_tokens = max_output_tokens
        self.console = console or Console(highlight=False)
        self.client = OpenAIResponses(api_key)
        self.previous_response_id: str | None = None
        self.total_input = 0
        self.total_output = 0
        self.last_input = 0
        self.last_output = 0
        self.last_cached = 0
        self.active_tools: set[str] = set()
        self.journal = MutationJournal()
        self.bridge = LocalMCPBridge(
            state, self.console, autopilot, dangerous, self.journal, work_mode=self.work_mode
        )

    def close(self) -> None:
        self.client.close()
        self.bridge.close()

    def _tools(self) -> list[dict[str, Any]]:
        return self.bridge.openai_tools(self.active_tools) + _function_tools()

    def _payload(self, input_data: Any, previous: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "instructions": SYSTEM_PROMPT + "\n\n" + PLATFORM_CONTEXT + _workflow_prompt(self.work_mode, self.tier),
            "input": input_data,
            "tools": self._tools(),
            "max_output_tokens": self.max_output_tokens,
            "store": True,
        }
        if self.reasoning != "none":
            payload["reasoning"] = {"effort": self.reasoning}
        if previous:
            payload["previous_response_id"] = previous
        return payload

    def _execute_tool(self, item: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        name = str(item.get("name", ""))
        try:
            arguments = json.loads(item.get("arguments") or "{}")
        except ValueError:
            return {"ok": False, "error": "Model supplied invalid JSON arguments."}, True
        if not isinstance(arguments, dict):
            return {"ok": False, "error": "Tool arguments must be an object."}, True
        if name == "opal_tool_search":
            names = self.bridge.search_tool_names(str(arguments.get("query", "")), int(arguments.get("limit", 8)))
            self.active_tools.update(names)
            return {"ok": True, "tools": self.bridge.catalog(names)}, False
        if name in {"ssh_exec", "vibeshell_adopt", "opal_wait_ready", "vibeshell_status"}:
            if WORK_MODES[self.work_mode]["read_only"]:
                if name == "vibeshell_adopt":
                    return {"ok": False, "blocked": True, "error": f"{WORK_MODES[self.work_mode]['label']} mode is read-only."}, True
                if name == "ssh_exec":
                    command = str(arguments.get("command", ""))
                    if not _shell_is_observational(command):
                        return {"ok": False, "blocked": True, "error": f"{WORK_MODES[self.work_mode]['label']} mode permits observational shell commands only."}, True
            self.console.print(f"[dim]→ local.{name}[/dim]")
            result = _execute_function(
                self.state, item, self.console, self.autopilot, self.dangerous, self.journal
            )
            if name == "vibeshell_adopt" and bool(result.get("ok")):
                self.bridge.refresh()
                self.active_tools.update(self.bridge.search_tool_names("vibeshell files logs shell_run", 8))
            return result, not bool(result.get("ok", True))
        return self.bridge.execute(name, arguments)

    def turn(self, prompt: str) -> str:
        self.last_input = self.last_output = self.last_cached = 0
        self.active_tools = set(self.bridge.search_tool_names(prompt, 8))
        response = self.client.create(self._payload(prompt, self.previous_response_id))
        while True:
            inp, out = _usage(response)
            cached = _cached_usage(response)
            self.total_input += inp
            self.total_output += out
            self.last_input += inp
            self.last_output += out
            self.last_cached += cached
            continuation: list[dict[str, Any]] = []
            for item in response.get("output", []):
                if not isinstance(item, dict) or item.get("type") != "function_call":
                    continue
                result, _ = self._execute_tool(item)
                continuation.append(
                    {
                        "type": "function_call_output",
                        "call_id": item["call_id"],
                        "output": json.dumps(result, ensure_ascii=False),
                    }
                )
            if continuation:
                response = self.client.create(self._payload(continuation, response["id"]))
                continue
            self.previous_response_id = response["id"]
            return _message_text(response) or "(completed with no text output)"

    def clear(self) -> None:
        self.previous_response_id = None
        self.active_tools.clear()

    def set_preset(self, preset: str) -> None:
        self.model, self.reasoning = OPENAI_MODEL_PRESETS[preset]
        self.tier = {"cheap": "lean", "default": "normal", "deep": "heavy"}[preset]
        self.tier_locked = True

    def set_tier(self, tier: str, locked: bool = True) -> None:
        self.tier = tier
        self.tier_locked = locked
        self.model, self.reasoning = _tier_model(self.provider, tier)

    def set_mode(self, work_mode: str) -> None:
        self.work_mode = _resolve_work_mode(work_mode)
        self.bridge.work_mode = self.work_mode
        if not self.tier_locked:
            self.set_tier(WORK_MODES[self.work_mode]["default_tier"], locked=False)


class AnthropicAgentSession:
    provider = "anthropic"

    def __init__(
        self,
        state,
        api_key: str,
        model: str | None = None,
        reasoning: str | None = None,
        autopilot: bool = False,
        max_output_tokens: int = 4096,
        console: Console | None = None,
        dangerous: bool = False,
        work_mode: str | None = None,
        tier: str | None = None,
    ):
        self.state = state
        self.work_mode = _resolve_work_mode(work_mode)
        self.tier, self.tier_locked = _resolve_tier(self.work_mode, tier)
        default_model, default_reasoning = _tier_model(self.provider, self.tier)
        self.model_override = model is not None or bool(os.environ.get("OPAL_AGENT_MODEL"))
        self.reasoning_override = reasoning is not None or bool(os.environ.get("OPAL_AGENT_REASONING"))
        self.tier_locked = self.tier_locked or self.model_override or self.reasoning_override
        self.model, self.reasoning = _model_settings(
            state, self.provider, model or (None if self.model_override else default_model),
            reasoning or (None if self.reasoning_override else default_reasoning),
        )
        self.autopilot = autopilot
        self.dangerous = dangerous
        self.max_output_tokens = max_output_tokens
        self.console = console or Console(highlight=False)
        self.client = AnthropicMessages(api_key)
        self.messages: list[dict[str, Any]] = []
        self.total_input = 0
        self.total_output = 0
        self.last_input = 0
        self.last_output = 0
        self.last_cached = 0
        self.active_tools: set[str] = set()
        self.journal = MutationJournal()
        self.bridge = LocalMCPBridge(
            state, self.console, autopilot, dangerous, self.journal, work_mode=self.work_mode
        )
        # 0.2.1 compatibility aliases; runtime is now shared/provider-neutral.
        self._tool_runtime = self.bridge.runtime
        self._mcp_clients = self.bridge.clients
        self._remote_tools: list[dict[str, Any]] = []

    def close(self) -> None:
        self.client.close()
        self.bridge.close()

    def _tools(self) -> list[dict[str, Any]]:
        return self.bridge.anthropic_tools(self.active_tools) + _anthropic_local_tools()

    def _payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_output_tokens,
            "system": SYSTEM_PROMPT + "\n\n" + PLATFORM_CONTEXT + _workflow_prompt(self.work_mode, self.tier),
            "messages": self.messages,
            "tools": self._tools(),
        }
        model_lower = self.model.lower()
        if self.reasoning == "none":
            if "sonnet-5-5" in model_lower:
                payload["thinking"] = {"type": "between_tools"}
                payload["output_config"] = {"effort": "low"}
            elif "opus-5-5" in model_lower:
                payload["output_config"] = {"effort": "low"}
            elif model_lower in {"claude-sonnet-5", "claude-opus-5"}:
                payload["thinking"] = {"type": "disabled"}
                payload["output_config"] = {"effort": "low"}
        elif "haiku" not in model_lower:
            payload["output_config"] = {"effort": self.reasoning}
        return payload

    def _execute_tool(self, block: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        name = str(block.get("name", ""))
        arguments = block.get("input")
        if not isinstance(arguments, dict):
            return {"ok": False, "error": "Model supplied non-object tool input."}, True
        if name == "opal_tool_search":
            names = self.bridge.search_tool_names(str(arguments.get("query", "")), int(arguments.get("limit", 8)))
            self.active_tools.update(names)
            return {"ok": True, "tools": self.bridge.catalog(names)}, False
        if name in {"ssh_exec", "vibeshell_adopt", "opal_wait_ready", "vibeshell_status"}:
            if WORK_MODES[self.work_mode]["read_only"]:
                if name == "vibeshell_adopt":
                    return {"ok": False, "blocked": True, "error": f"{WORK_MODES[self.work_mode]['label']} mode is read-only."}, True
                if name == "ssh_exec":
                    command = str(arguments.get("command", ""))
                    if not _shell_is_observational(command):
                        return {"ok": False, "blocked": True, "error": f"{WORK_MODES[self.work_mode]['label']} mode permits observational shell commands only."}, True
            self.console.print(f"[dim]→ local.{name}[/dim]")
            result = _execute_function(
                self.state,
                {"name": name, "arguments": json.dumps(arguments)},
                self.console,
                self.autopilot,
                self.dangerous,
                self.journal,
            )
            if name == "vibeshell_adopt" and bool(result.get("ok")):
                self.bridge.refresh()
                self.active_tools.update(self.bridge.search_tool_names("vibeshell files logs shell_run", 8))
            return result, not bool(result.get("ok", True))
        return self.bridge.execute(name, arguments)

    def turn(self, prompt: str) -> str:
        self.last_input = self.last_output = self.last_cached = 0
        self.active_tools = set(self.bridge.search_tool_names(prompt, 8))
        self.messages.append({"role": "user", "content": prompt})
        while True:
            response = self.client.create(self._payload())
            inp, out = _anthropic_usage(response)
            raw_usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
            cached = int(raw_usage.get("cache_read_input_tokens") or 0)
            self.total_input += inp
            self.total_output += out
            self.last_input += inp
            self.last_output += out
            self.last_cached += cached
            content = response.get("content", [])
            if not isinstance(content, list):
                raise AgentError("Anthropic returned an unexpected content shape.")
            self.messages.append({"role": "assistant", "content": content})
            calls = [block for block in content if isinstance(block, dict) and block.get("type") == "tool_use"]
            if not calls:
                return _anthropic_message_text(response) or "(completed with no text output)"
            results: list[dict[str, Any]] = []
            for block in calls:
                result, is_error = self._execute_tool(block)
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": json.dumps(result, ensure_ascii=False),
                        "is_error": is_error,
                    }
                )
            self.messages.append({"role": "user", "content": results})

    def clear(self) -> None:
        self.messages.clear()
        self.active_tools.clear()

    def set_preset(self, preset: str) -> None:
        self.model, self.reasoning = ANTHROPIC_MODEL_PRESETS[preset]
        self.tier = {"cheap": "lean", "default": "normal", "deep": "heavy"}[preset]
        self.tier_locked = True

    def set_tier(self, tier: str, locked: bool = True) -> None:
        self.tier = tier
        self.tier_locked = locked
        self.model, self.reasoning = _tier_model(self.provider, tier)

    def set_mode(self, work_mode: str) -> None:
        self.work_mode = _resolve_work_mode(work_mode)
        self.bridge.work_mode = self.work_mode
        if not self.tier_locked:
            self.set_tier(WORK_MODES[self.work_mode]["default_tier"], locked=False)


class OllamaAgentSession:
    provider = "ollama"

    def __init__(
        self, state, api_key: str = "", model: str | None = None, reasoning: str | None = None,
        autopilot: bool = False, max_output_tokens: int = 4096, console: Console | None = None,
        dangerous: bool = False, work_mode: str | None = None, tier: str | None = None,
    ):
        self.state = state
        self.work_mode = _resolve_work_mode(work_mode)
        self.tier, self.tier_locked = _resolve_tier(self.work_mode, tier)
        default_model, default_reasoning = _tier_model(self.provider, self.tier)
        self.model_override = model is not None or bool(os.environ.get("OPAL_AGENT_MODEL"))
        self.reasoning_override = reasoning is not None or bool(os.environ.get("OPAL_AGENT_REASONING"))
        self.tier_locked = self.tier_locked or self.model_override or self.reasoning_override
        saved = _agent_profile(state)
        self.model = model or os.environ.get("OPAL_AGENT_MODEL") or saved.get("ollama_model") or default_model
        self.reasoning = reasoning or os.environ.get("OPAL_AGENT_REASONING") or saved.get("reasoning") or default_reasoning
        self.autopilot = autopilot
        self.dangerous = dangerous
        self.max_output_tokens = max_output_tokens
        self.console = console or Console(highlight=False)
        self.client = OllamaChat(_ollama_base_url(), api_key)
        self.messages: list[dict[str, Any]] = []
        self.total_input = self.total_output = 0
        self.last_input = self.last_output = self.last_cached = 0
        self.active_tools: set[str] = set()
        self.journal = MutationJournal()
        self.bridge = LocalMCPBridge(state, self.console, autopilot, dangerous, self.journal, work_mode=self.work_mode)

    def close(self) -> None:
        self.client.close()
        self.bridge.close()

    def _tools(self) -> list[dict[str, Any]]:
        return _openai_chat_tools(self.bridge.openai_tools(self.active_tools) + _function_tools())

    def _payload(self) -> dict[str, Any]:
        messages = [{"role": "system", "content": SYSTEM_PROMPT + "\n\n" + PLATFORM_CONTEXT + _workflow_prompt(self.work_mode, self.tier)}]
        messages.extend(self.messages)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "tools": self._tools(),
            "stream": False,
            "max_tokens": self.max_output_tokens,
        }
        if self.reasoning != "none":
            payload["reasoning_effort"] = self.reasoning
        return payload

    def _execute_tool(self, call: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        fn = call.get("function") if isinstance(call.get("function"), dict) else {}
        name = str(fn.get("name", ""))
        raw_args = fn.get("arguments", {})
        if isinstance(raw_args, str):
            try:
                arguments = json.loads(raw_args or "{}")
            except ValueError:
                return {"ok": False, "error": "Model supplied invalid JSON arguments."}, True
        else:
            arguments = raw_args
        if not isinstance(arguments, dict):
            return {"ok": False, "error": "Tool arguments must be an object."}, True
        if name == "opal_tool_search":
            names = self.bridge.search_tool_names(str(arguments.get("query", "")), int(arguments.get("limit", 8)))
            self.active_tools.update(names)
            return {"ok": True, "tools": self.bridge.catalog(names)}, False
        if name in {"ssh_exec", "vibeshell_adopt", "opal_wait_ready", "vibeshell_status"}:
            if WORK_MODES[self.work_mode]["read_only"]:
                if name == "vibeshell_adopt":
                    return {"ok": False, "blocked": True, "error": f"{WORK_MODES[self.work_mode]['label']} mode is read-only."}, True
                if name == "ssh_exec" and not _shell_is_observational(str(arguments.get("command", ""))):
                    return {"ok": False, "blocked": True, "error": f"{WORK_MODES[self.work_mode]['label']} mode permits observational shell commands only."}, True
            self.console.print(f"[dim]→ local.{name}[/dim]")
            result = _execute_function(
                self.state, {"name": name, "arguments": json.dumps(arguments)}, self.console,
                self.autopilot, self.dangerous, self.journal,
            )
            if name == "vibeshell_adopt" and bool(result.get("ok")):
                self.bridge.refresh()
                self.active_tools.update(self.bridge.search_tool_names("vibeshell files logs shell_exec shell_run", 8))
            return result, not bool(result.get("ok", True))
        return self.bridge.execute(name, arguments)

    def turn(self, prompt: str) -> str:
        self.last_input = self.last_output = self.last_cached = 0
        self.active_tools = set(self.bridge.search_tool_names(prompt, 8))
        self.messages.append({"role": "user", "content": prompt})
        while True:
            response = self.client.create(self._payload())
            inp, out = _chat_usage(response)
            self.total_input += inp; self.total_output += out
            self.last_input += inp; self.last_output += out
            choices = response.get("choices", [])
            if not choices or not isinstance(choices[0], dict):
                raise AgentError("Ollama returned no choices.")
            message = choices[0].get("message")
            if not isinstance(message, dict):
                raise AgentError("Ollama returned an unexpected message shape.")
            assistant_message = {"role": "assistant", "content": message.get("content") or ""}
            raw_calls = message.get("tool_calls") if isinstance(message.get("tool_calls"), list) else []
            calls: list[dict[str, Any]] = []
            for idx, raw_call in enumerate(raw_calls):
                if not isinstance(raw_call, dict):
                    continue
                call = dict(raw_call)
                call["id"] = str(call.get("id") or f"call_{idx}")
                calls.append(call)
            if calls:
                assistant_message["tool_calls"] = calls
            self.messages.append(assistant_message)
            if not calls:
                return str(message.get("content") or "(completed with no text output)")
            for call in calls:
                result, _ = self._execute_tool(call)
                call_id = str(call["id"])
                self.messages.append({
                    "role": "tool", "tool_call_id": call_id,
                    "content": json.dumps(result, ensure_ascii=False),
                })

    def clear(self) -> None:
        self.messages.clear()
        self.active_tools.clear()

    def set_preset(self, preset: str) -> None:
        tier = {"cheap": "lean", "default": "normal", "deep": "heavy"}[preset]
        self.set_tier(tier, locked=True)

    def set_tier(self, tier: str, locked: bool = True) -> None:
        self.tier = tier
        self.tier_locked = locked
        self.model, self.reasoning = _tier_model(self.provider, tier)

    def set_mode(self, work_mode: str) -> None:
        self.work_mode = _resolve_work_mode(work_mode)
        self.bridge.work_mode = self.work_mode
        if not self.tier_locked:
            self.set_tier(WORK_MODES[self.work_mode]["default_tier"], locked=False)


class AgentSession:
    """Provider-selecting session facade kept for backwards compatibility."""

    def __new__(
        cls,
        state,
        model: str | None = None,
        reasoning: str | None = None,
        autopilot: bool = False,
        max_output_tokens: int = 4096,
        console: Console | None = None,
        provider: str | None = None,
        dangerous: bool = False,
        work_mode: str | None = None,
        tier: str | None = None,
    ):
        resolved, api_key = _resolve_provider(provider)
        session_cls = {
            "openai": OpenAIAgentSession,
            "anthropic": AnthropicAgentSession,
            "ollama": OllamaAgentSession,
        }[resolved]
        return session_cls(
            state, api_key, model, reasoning, autopilot, max_output_tokens, console, dangerous,
            work_mode=work_mode, tier=tier,
        )


def _safety_label(session) -> str:
    if session.dangerous:
        return "DANGEROUS/REVIEWED"
    if session.autopilot:
        return "SAFE/AUTO"
    return "SAFE/REVIEWED"


def _print_status(console: Console, state, session) -> None:
    connected = bool(_try_opal_token(state))
    console.print(
        f"[bold cyan]mode[/bold cyan]      {WORK_MODES[session.work_mode]['label']} — {WORK_MODES[session.work_mode]['description']}\n"
        f"[bold cyan]tier[/bold cyan]      {session.tier.upper()} {'(manual)' if session.tier_locked else '(mode default)'}\n"
        f"[bold cyan]model[/bold cyan]     {session.provider} / {session.model} / reasoning {session.reasoning}\n"
        f"[bold cyan]account[/bold cyan]   {'connected' if connected else 'NOT CONNECTED'} / profile {state.profile}\n"
        f"[bold cyan]tools[/bold cyan]     {len(session.active_tools)} active / {len(session.bridge.definitions)} catalog / {len(load_vibes(state))} VibeShell endpoints\n"
        f"[bold cyan]safety[/bold cyan]    {_safety_label(session)}\n"
        f"[bold cyan]last turn[/bold cyan] {session.last_input:,} in ({session.last_cached:,} cached) / {session.last_output:,} out\n"
        f"[bold cyan]session[/bold cyan]   {session.total_input:,} in / {session.total_output:,} out\n"
        f"[bold cyan]journal[/bold cyan]   {session.journal.path}"
    )


def print_banner(console: Console, state, session) -> None:
    art = Text()
    shades = ["#e9d5ff", "#ddd6fe", "#c4b5fd", "#c084fc", "#a78bfa", "#a855f7", "#9333ea", "#8b5cf6", "#7c3aed", "#6d28d9", "#5b21b6"]
    for idx, line in enumerate(BANNER.splitlines()):
        art.append(line, style=f"bold {shades[min(idx, len(shades)-1)]}")
        if idx != len(BANNER.splitlines()) - 1:
            art.append("\n")
    console.print(art)
    connected = _try_opal_token(state) is not None
    account = "[bold green]CONNECTED[/bold green]" if connected else "[bold red]NOT CONNECTED[/bold red]"
    console.print(
        f"[bold cyan]{WORK_MODES[session.work_mode]['label']}[/bold cyan]  "
        f"[yellow]{session.tier.upper()}[/yellow]  "
        f"[magenta]{session.provider.upper()}[/magenta]  "
        f"OPALSTACK {account}  "
        f"{_safety_label(session)}\n"
    )


def _turn_usage_line(session) -> str:
    cached = f" / {session.last_cached:,} cached" if session.last_cached else ""
    return (
        f"{session.tier.upper()} · {session.model} · "
        f"last turn {session.last_input:,} in{cached} / {session.last_output:,} out"
    )


def _clear_screen() -> None:
    # Stay on the normal terminal screen buffer so native scrollback is preserved by the terminal.
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def repl(
    state,
    model: str | None = None,
    reasoning: str | None = None,
    autopilot: bool = False,
    max_output_tokens: int = 4096,
    provider: str | None = None,
    dangerous: bool = False,
    work_mode: str | None = None,
    tier: str | None = None,
) -> None:
    session = AgentSession(
        state, model, reasoning, autopilot, max_output_tokens, provider=provider, dangerous=dangerous,
        work_mode=work_mode, tier=tier,
    )
    console = session.console
    shell = _prompt_session()
    transcript = SessionTranscript()
    command_history: list[str] = []
    print_banner(console, state, session)
    if _try_opal_token(state) is None:
        console.print("[yellow]No Opalstack Vibe token configured. Run: opalagent auth login[/yellow]")
    console.print(
        "[dim]PLAN talks it through · /execute builds · /mode ops debugs · Ctrl-R history · Alt-Enter newline · /help[/dim]\n"
    )
    try:
        while True:
            try:
                mode_label = WORK_MODES[session.work_mode]["label"]
                prompt = shell.prompt(ANSI(
                    f"\x1b[35;1mopal\x1b[0m \x1b[36;1m[{mode_label}]\x1b[0m › "
                )).strip()
            except KeyboardInterrupt:
                console.print("[dim]^C[/dim]")
                continue
            except EOFError:
                console.print()
                break
            if not prompt:
                continue
            command_history.append(prompt)
            if prompt in {"/exit", "/quit", "exit", "quit"}:
                break
            if prompt == "/help":
                console.print(
                    "[bold]WORK[/bold]\n"
                    "  /mode plan|build|ops|manage   choose the kind of work\n"
                    "  /execute                      execute the agreed plan in BUILD\n"
                    "  /tier auto|lean|normal|heavy choose cost/reasoning\n\n"
                    "[bold]SHELL[/bold]\n"
                    "  Ctrl-R                        search persistent command history\n"
                    "  Up/Down                       walk command history\n"
                    "  Alt-Enter                     insert a newline\n"
                    "  Ctrl-C                        cancel current input\n"
                    "  Ctrl-D                        exit when input is empty\n"
                    "  /history [n]                  commands from this session\n"
                    "  /scroll [n]                   reprint recent OPAL conversation\n"
                    "  /save <file>                  save session transcript\n"
                    "  /clear                        clear screen (does not forget context)\n"
                    "  /reset                        forget model conversation context\n\n"
                    "[bold]INFO[/bold]\n"
                    "  /status   /vibes   /exit\n\n"
                    "Native terminal scrollback stays enabled; OPAL never switches to the alternate screen."
                )
                continue
            if prompt in {"/reset", "/forget"}:
                session.clear()
                transcript.add("system", "model conversation context reset")
                console.print("[dim]model conversation reset; shell history/scrollback kept[/dim]")
                continue
            if prompt in {"/clear", "clear"}:
                _clear_screen()
                print_banner(console, state, session)
                continue
            if prompt.startswith("/history"):
                parts = prompt.split()
                try:
                    limit = int(parts[1]) if len(parts) > 1 else 30
                except ValueError:
                    console.print("[red]usage: /history [number][/red]")
                    continue
                for i, item in enumerate(command_history[-max(1, limit):], start=max(1, len(command_history)-limit+1)):
                    console.print(f"[dim]{i:>4}[/dim]  {item}")
                continue
            if prompt.startswith("/scroll"):
                parts = prompt.split()
                try:
                    limit = int(parts[1]) if len(parts) > 1 else 20
                except ValueError:
                    console.print("[red]usage: /scroll [number][/red]")
                    continue
                transcript.render(console, limit)
                continue
            if prompt.startswith("/save "):
                dest = prompt.split(None, 1)[1].strip()
                if not dest:
                    console.print("[red]usage: /save <file>[/red]")
                    continue
                try:
                    saved = transcript.save(dest)
                except OSError as exc:
                    console.print(f"[red]could not save transcript:[/red] {exc}")
                else:
                    console.print(f"[dim]saved transcript → {saved}[/dim]")
                continue
            if prompt in {"/plan", "/build", "/ops", "/manage"}:
                prompt = "/mode " + prompt[1:]
            if prompt.startswith("/mode "):
                value = prompt.split(None, 1)[1].strip().lower()
                if value not in WORK_MODES:
                    console.print("[red]choose plan, build, ops, or manage[/red]")
                else:
                    session.set_mode(value)
                    console.print(
                        f"[bold cyan]{WORK_MODES[value]['label']}[/bold cyan] — {WORK_MODES[value]['description']} "
                        f"[dim](tier {session.tier.upper()})[/dim]"
                    )
                continue
            if prompt.startswith("/tier "):
                value = prompt.split(None, 1)[1].strip().lower()
                if value == "auto":
                    session.tier_locked = False
                    session.set_tier(WORK_MODES[session.work_mode]["default_tier"], locked=False)
                    console.print(f"[dim]tier → {session.tier.upper()} (mode default); model → {session.model}[/dim]")
                elif value not in TIER_TO_PRESET:
                    console.print("[red]choose auto, lean, normal, or heavy[/red]")
                else:
                    session.set_tier(value, locked=True)
                    console.print(f"[dim]tier → {session.tier.upper()} (manual); model → {session.model}[/dim]")
                continue
            if prompt == "/execute":
                if session.work_mode == "build":
                    console.print("[dim]already in BUILD mode[/dim]")
                    continue
                session.set_mode("build")
                console.print(f"[bold cyan]BUILD[/bold cyan] — executing the agreed plan [dim](tier {session.tier.upper()})[/dim]")
                prompt = (
                    "Execute the plan we just agreed on. Re-check current state before changing anything, "
                    "make small reversible changes, test/verify each stage, and stop if reality differs materially from the plan."
                )
            elif prompt.startswith("/model "):
                preset = prompt.split(None, 1)[1].strip()
                if preset not in MODEL_PRESETS:
                    console.print("[red]choose cheap, default, or deep (or use /tier lean|normal|heavy)[/red]")
                else:
                    session.set_preset(preset)
                    console.print(f"[dim]tier → {session.tier.upper()}; model → {session.model} ({session.reasoning})[/dim]")
                continue
            elif prompt.startswith("/reasoning "):
                value = prompt.split(None, 1)[1].strip()
                if value not in {"none", "low", "medium", "high", "xhigh", "max"}:
                    console.print("[red]invalid reasoning effort[/red]")
                else:
                    session.reasoning = value
                    session.reasoning_override = True
                    session.tier_locked = True
                    console.print(f"[dim]reasoning → {value} (manual override)[/dim]")
                continue
            elif prompt == "/vibes":
                vibes = load_vibes(state)
                if not vibes:
                    console.print("[dim]no VibeShell endpoints configured[/dim]")
                else:
                    for vibe in vibes:
                        console.print(f"[cyan]{vibe.label}[/cyan]  {vibe.user or '?'}  {vibe.url}  {vibe.base_dir or ''}")
                continue
            elif prompt == "/status":
                _print_status(console, state, session)
                continue
            elif prompt.startswith("/dangerous"):
                console.print("[yellow]dangerous mode cannot be enabled from inside a live session; exit and start: opalagent --dangerous[/yellow]")
                continue
            elif prompt.startswith("/"):
                console.print(f"[red]unknown command:[/red] {prompt.split()[0]}  [dim](type /help)[/dim]")
                continue
            transcript.add("user", prompt)
            try:
                answer = session.turn(prompt)
                transcript.add("opal", answer)
                console.print(Panel(answer, title=f"OPAL · {WORK_MODES[session.work_mode]['label']}", border_style="cyan"))
                console.print(f"[dim]{_turn_usage_line(session)}[/dim]\n")
            except click.ClickException as exc:
                message = exc.format_message()
                transcript.add("system", f"Error: {message}")
                console.print(f"[red]Error:[/red] {message}")
    finally:
        session.close()


def one_shot(
    state,
    prompt: str,
    model: str | None = None,
    reasoning: str | None = None,
    autopilot: bool = False,
    max_output_tokens: int = 4096,
    provider: str | None = None,
    dangerous: bool = False,
    work_mode: str | None = None,
    tier: str | None = None,
) -> str:
    session = AgentSession(
        state, model, reasoning, autopilot, max_output_tokens, provider=provider, dangerous=dangerous,
        work_mode=work_mode, tier=tier,
    )
    try:
        return session.turn(prompt)
    finally:
        session.close()

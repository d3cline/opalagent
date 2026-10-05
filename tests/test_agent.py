import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from opalstack_cli import agent, config


def state(tmp_path, monkeypatch):
    monkeypatch.setenv("OPALSTACK_CONFIG", str(tmp_path / "config.json"))
    return SimpleNamespace(
        profile="default",
        data={"default": "default", "profiles": {"default": {"token": "opal-token", "storage": "file"}}},
    )


def test_model_presets_are_cost_tiered():
    assert agent.MODEL_PRESETS["cheap"][0] == "gpt-5.6-luna"
    assert agent.MODEL_PRESETS["default"][0] == "gpt-5.6-terra"
    assert agent.MODEL_PRESETS["deep"][0] == "gpt-5.6-sol"


def test_endpoint_requires_https():
    with pytest.raises(agent.AgentError):
        agent.normalize_endpoint("http://example.com/mcp")
    assert agent.normalize_endpoint("https://example.com/mcp") == "https://example.com/mcp/"


def test_vibe_secret_stored_but_not_public(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    vibe = agent.VibeEndpoint("prod", "https://v.example/", "super-secret", "web", "vibeshell", "~/apps")
    agent.save_vibe(s, vibe)
    saved = json.loads((tmp_path / "config.json").read_text())
    assert saved["profiles"]["default"]["agent"]["vibeshells"][0]["token"] == "super-secret"
    assert "token" not in vibe.public()
    assert (tmp_path / "config.json").stat().st_mode & 0o077 == 0


def test_mcp_specs_keep_tokens_local(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    agent.save_vibe(s, agent.VibeEndpoint("prod", "https://v.example/", "vibe-token", "web", "vibeshell", "~/apps"))
    specs = agent._mcp_server_specs(s)
    assert [spec["label"] for spec in specs] == ["opalstack", "vibe_prod"]
    assert specs[0]["url"] == agent.OPALSTACK_MCP_URL
    assert specs[0]["token"] == "opal-token"
    assert specs[1]["token"] == "vibe-token"
    assert all("headers" not in spec for spec in specs)

def test_ssh_cwd_expands_home_without_shell_tilde_bug(monkeypatch):
    s = SimpleNamespace()
    monkeypatch.setattr(agent, "_ssh_target", lambda state, user: ({}, "alice", "opal.example"))
    monkeypatch.setattr(agent, "_approve", lambda *a, **kw: True)
    proc = Mock(returncode=0, stdout="ok\n", stderr="")
    monkeypatch.setattr(agent.subprocess, "run", lambda *a, **kw: proc if "input" not in kw else Mock(returncode=0, stdout="ok\n", stderr=""))
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["input"] = kwargs.get("input")
        return Mock(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    result = agent.ssh_exec(
        s,
        {"user": "alice", "command": "pytest -q", "cwd": "~/apps/demo", "timeout": 30},
        Console(file=None, force_terminal=False),
        autopilot=True,
    )
    assert result["ok"] is True
    assert 'cd "$HOME"/apps/demo' in seen["input"]


def test_ssh_rejects_cwd_escape(monkeypatch):
    s = SimpleNamespace()
    monkeypatch.setattr(agent, "_ssh_target", lambda state, user: ({}, "alice", "opal.example"))
    result = agent.ssh_exec(
        s,
        {"user": "alice", "command": "pwd", "cwd": "~/apps/../secrets", "timeout": 30},
        Console(file=None, force_terminal=False),
        autopilot=True,
    )
    assert result["ok"] is False
    assert "inside" in result["error"]


def test_payload_resends_tools_and_instructions(monkeypatch):
    s = SimpleNamespace(profile="default", data={"default": "default", "profiles": {"default": {"token": "opal-token"}}})
    monkeypatch.setenv("OPENAI_API_KEY", "model-key")
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.AgentSession(s)
    try:
        payload = session._payload([{"type": "function_call_output", "call_id": "c", "output": "{}"}], "resp_1")
        assert payload["previous_response_id"] == "resp_1"
        assert payload["instructions"].startswith(agent.SYSTEM_PROMPT)
        assert "Mode: PLAN" in payload["instructions"]
        assert "Cost tier: NORMAL" in payload["instructions"]
        assert all(tool.get("type") != "mcp" for tool in payload["tools"])
        assert any(tool.get("name") == "ssh_exec" for tool in payload["tools"])
    finally:
        session.close()


def test_base_dir_rejects_ini_and_path_escape():
    assert agent.normalize_base_dir("~/apps/demo") == "~/apps/demo"
    assert agent.normalize_base_dir("~") == "~"
    with pytest.raises(agent.AgentError):
        agent.normalize_base_dir('~/apps/demo"\nallow_exec=true')
    with pytest.raises(agent.AgentError):
        agent.normalize_base_dir("~/apps/../secrets")
    with pytest.raises(agent.AgentError):
        agent.normalize_base_dir("/tmp")


def test_adopt_tool_has_no_secret_argument():
    adopt = next(t for t in agent._function_tools() if t.get("name") == "vibeshell_adopt")
    props = adopt["parameters"]["properties"]
    assert "token" not in props
    assert adopt["parameters"]["required"] == ["user", "app", "endpoint_url", "label"]


def test_vibeshell_installer_config_reads_nonsecret_hints():
    app = {"json": {"vibeshell_base_dir": "~", "vibeshell_endpoint": "https://v.example/mcp"}}
    cfg = agent._vibeshell_installer_config(app)
    assert "token" not in cfg
    assert cfg["base_dir"] == "~"
    assert cfg["endpoint"] == "https://v.example/mcp"


def test_vibeshell_notice_credential_matches_application_id(monkeypatch):
    token = "a" * 64
    notices = [
        {"id": "n1", "content": "Created MCP VibeSHEL app other with Application ID: other-id / Bearer key: " + "b" * 64},
        {"id": "n2", "content": "Created MCP VibeSHEL app vibeshell with Application ID: a1 / Bearer key: " + token},
    ]
    mgr = SimpleNamespace(list_all=lambda: notices)
    s = SimpleNamespace(manager=lambda resource: mgr if resource == "notices" else None)
    assert agent._vibeshell_notice_credential(s, {"id": "a1", "name": "vibeshell"}) == token


def test_vibeshell_notice_credential_rejects_unrelated_notice(monkeypatch):
    mgr = SimpleNamespace(list_all=lambda: [{"content": "Password: nope"}])
    s = SimpleNamespace(manager=lambda resource: mgr)
    with pytest.raises(agent.AgentError) as exc:
        agent._vibeshell_notice_credential(s, {"id": "a1", "name": "vibeshell"})
    assert "Notice Log" in exc.value.format_message()


def test_vibeshell_adopt_uses_notice_secret_locally(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    s.wait_timeout = 30
    user = {"id": "u1", "name": "alice"}
    app = {"id": "a1", "name": "vibeshell", "osuser": {"id": "u1"}, "json": {"vibeshell_base_dir": "~"}}
    monkeypatch.setattr(agent, "_resolve_user", lambda state, selector: user)
    monkeypatch.setattr(agent, "_resolve_app", lambda state, selector: app)
    monkeypatch.setattr(agent, "_wait_ready_object", lambda *a, **kw: {"ok": True, "ready": True, "status": "READY"})
    monkeypatch.setattr(agent, "_vibeshell_notice_credential", lambda state, app: "a" * 64)

    class FakeMCP:
        def __init__(self, url, token, timeout=20.0):
            assert token == "a" * 64
            self.url = url
        def list_tools(self):
            return [{"name": n} for n in ["fs_info", "fs_read", "fs_write", "fs_search", "shell_exec"]]
        def close(self): pass

    monkeypatch.setattr(agent, "MCPHttpClient", FakeMCP)
    result = agent.vibeshell_adopt(s, {"user": "alice", "app": "vibeshell", "endpoint_url": "https://v.example/mcp", "label": "alice"})
    assert result["ok"] is True
    assert result["state"] == "READY_EXEC"
    assert "token" not in json.dumps(result)
    assert "Notice Log" in result["note"]
    saved = json.loads((tmp_path / "config.json").read_text())
    assert saved["profiles"]["default"]["agent"]["vibeshells"][0]["token"] == "a" * 64


def test_notice_result_redacts_installer_credentials():
    raw = {"content": [{"type": "text", "text": "Created MCP VibeSHEL app v with Application ID: a / Bearer key: " + "a" * 64 + " Password: nope"}]}
    clean = agent._redact_notice_result(raw)
    blob = json.dumps(clean)
    assert "a" * 64 not in blob
    assert "Bearer key: [REDACTED]" in blob
    assert "Password: [REDACTED]" in blob


def test_provider_auto_selects_only_available_key(monkeypatch):
    monkeypatch.delenv("OPAL_AGENT_PROVIDER", raising=False)
    monkeypatch.delenv("OPAL_AGENT_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anth-key")
    assert agent._resolve_provider() == ("anthropic", "anth-key")


def test_provider_requires_one_model_key(monkeypatch):
    monkeypatch.delenv("OPAL_AGENT_PROVIDER", raising=False)
    monkeypatch.delenv("OPAL_AGENT_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(agent.AgentError) as exc:
        agent._resolve_provider()
    assert "OPENAI_API_KEY" in exc.value.format_message()
    assert "ANTHROPIC_API_KEY" in exc.value.format_message()


def test_provider_asks_when_both_keys_exist(monkeypatch):
    monkeypatch.delenv("OPAL_AGENT_PROVIDER", raising=False)
    monkeypatch.delenv("OPAL_AGENT_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "open-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anth-key")
    monkeypatch.setattr(agent.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    seen = {}

    def fake_prompt(text, **kwargs):
        seen["text"] = text
        return "anthropic"

    monkeypatch.setattr(agent.click, "prompt", fake_prompt)
    assert agent._resolve_provider() == ("anthropic", "anth-key")
    assert "Multiple model providers" in seen["text"]


def test_provider_both_noninteractive_requires_explicit_choice(monkeypatch):
    monkeypatch.delenv("OPAL_AGENT_PROVIDER", raising=False)
    monkeypatch.delenv("OPAL_AGENT_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "open-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anth-key")
    monkeypatch.setattr(agent.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(agent.AgentError) as exc:
        agent._resolve_provider()
    assert "--provider" in exc.value.format_message()


def test_anthropic_presets_are_provider_specific():
    assert agent.ANTHROPIC_MODEL_PRESETS["cheap"][0] == "claude-haiku-4-5-20251001"
    assert agent.ANTHROPIC_MODEL_PRESETS["default"][0] == "claude-sonnet-5-5"
    assert agent.ANTHROPIC_MODEL_PRESETS["deep"][0] == "claude-opus-5-5"


def test_anthropic_messages_uses_api_key_header(monkeypatch):
    client = agent.AnthropicMessages("anth-secret")
    seen = {}

    class Resp:
        status_code = 200
        def json(self):
            return {"id": "msg_1", "content": [], "usage": {}}

    def fake_post(url, **kwargs):
        seen["url"] = url
        seen["headers"] = kwargs["headers"]
        seen["json"] = kwargs["json"]
        return Resp()

    monkeypatch.setattr(client.session, "post", fake_post)
    try:
        result = client.create({"model": "claude-sonnet-5-5", "messages": [], "max_tokens": 256})
    finally:
        client.close()
    assert result["id"] == "msg_1"
    assert seen["url"] == agent.ANTHROPIC_MESSAGES_URL
    assert seen["headers"]["x-api-key"] == "anth-secret"
    assert seen["headers"]["anthropic-version"] == "2023-06-01"


def test_anthropic_session_uses_client_side_mcp_tools(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.AnthropicAgentSession(s, "anth-key")
    try:
        assert session.provider == "anthropic"
        assert session.model == "claude-sonnet-5-5"
        payload = session._payload()
        names = {tool["name"] for tool in payload["tools"]}
        assert "ssh_exec" in names
        assert "vibeshell_adopt" in names
        assert payload["output_config"]["effort"] == "low"
    finally:
        session.close()


def test_anthropic_haiku_omits_unsupported_effort(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.AnthropicAgentSession(s, "anth-key", model="claude-haiku-4-5-20251001", reasoning="low")
    try:
        assert "output_config" not in session._payload()
    finally:
        session.close()


def test_mcp_read_only_classifier_uses_action_and_vibe_names():
    assert agent._mcp_call_is_read_only("opalstack", {"name": "mcp_opalstack_application"}, {"action": "list"})
    assert not agent._mcp_call_is_read_only("opalstack", {"name": "mcp_opalstack_application"}, {"action": "delete"})
    assert agent._mcp_call_is_read_only("vibe_prod", {"name": "fs_read"}, {"path": "x"})
    assert not agent._mcp_call_is_read_only("vibe_prod", {"name": "shell_run"}, {"command": "true"})


def test_anthropic_mcp_mutation_still_uses_approval(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.AnthropicAgentSession(s, "anth-key", work_mode="build")

    class FakeMCP:
        def call_tool(self, name, arguments):
            return {"content": [{"type": "text", "text": "ok"}], "isError": False}

    session._tool_runtime["opalstack__apps"] = (
        "opalstack",
        FakeMCP(),
        {"name": "apps", "description": "apps"},
    )
    monkeypatch.setattr(agent, "_approve", lambda *a, **kw: False)
    try:
        result, is_error = session._execute_tool(
            {"name": "opalstack__apps", "input": {"action": "delete", "id": "x"}}
        )
    finally:
        session.close()
    assert is_error is True
    assert result["blocked"] is True
    assert "SAFE mode" in result["error"]


def test_anthropic_mcp_read_skips_approval(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.AnthropicAgentSession(s, "anth-key")
    called = {"tool": False, "approve": False}

    class FakeMCP:
        def call_tool(self, name, arguments):
            called["tool"] = True
            return {"content": [{"type": "text", "text": "ok"}], "isError": False}

    session._tool_runtime["opalstack__apps"] = (
        "opalstack",
        FakeMCP(),
        {"name": "apps", "description": "apps"},
    )

    def fake_approve(*args, **kwargs):
        called["approve"] = True
        return False

    monkeypatch.setattr(agent, "_approve", fake_approve)
    try:
        result, is_error = session._execute_tool(
            {"name": "opalstack__apps", "input": {"action": "list"}}
        )
    finally:
        session.close()
    assert is_error is False
    assert called["tool"] is True
    assert called["approve"] is False
    assert result["isError"] is False


def test_agent_session_factory_selects_anthropic(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.delenv("OPAL_AGENT_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anth-key")
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.AgentSession(s)
    try:
        assert isinstance(session, agent.AnthropicAgentSession)
        assert session.provider == "anthropic"
    finally:
        session.close()


def test_anthropic_text_turn_tracks_history_and_usage(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.AnthropicAgentSession(s, "anth-key")
    response = {
        "id": "msg_1",
        "content": [{"type": "text", "text": "roger"}],
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }
    monkeypatch.setattr(session.client, "create", lambda payload: response)
    try:
        assert session.turn("status") == "roger"
        assert session.total_input == 12
        assert session.total_output == 3
        assert session.messages[0] == {"role": "user", "content": "status"}
        assert session.messages[1]["role"] == "assistant"
    finally:
        session.close()


def test_openai_session_uses_local_mcp_function_tools(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)

    class FakeMCP:
        def __init__(self, url, token):
            self.url = url
            self.token = token
        def list_tools(self):
            return [{
                "name": "apps",
                "description": "Manage apps",
                "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}}},
            }]
        def call_tool(self, name, arguments):
            return {"isError": False, "content": [{"type": "text", "text": "ok"}]}
        def close(self):
            pass

    monkeypatch.setattr(agent, "MCPHttpClient", FakeMCP)
    session = agent.OpenAIAgentSession(s, "open-key")
    try:
        # MCP schemas are lazy in 0.2.4: irrelevant tools are not sent on every turn.
        assert all(t.get("name") != "opalstack__apps" for t in session._payload("hello")["tools"])
        session.active_tools.update(session.bridge.search_tool_names("apps", 8))
        tools = session._payload("show apps")["tools"]
        remote = next(t for t in tools if t.get("name") == "opalstack__apps")
        assert remote["type"] == "function"
        assert all(t.get("type") != "mcp" for t in tools)
        assert session.bridge.clients[0].token == "opal-token"
        serialized = json.dumps(session._payload("hello"))
        assert "opal-token" not in serialized
        assert "server_url" not in serialized
        assert agent.OPALSTACK_MCP_URL not in serialized
    finally:
        session.close()


def test_safe_mode_blocks_delete_even_with_autopilot(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), autopilot=True, work_mode="build")

    class FakeMCP:
        def call_tool(self, name, arguments):
            raise AssertionError("destructive call must never reach MCP in SAFE mode")

    bridge.runtime["opalstack__apps"] = (
        "opalstack", FakeMCP(), {"name": "apps", "description": "apps"}
    )
    try:
        result, is_error = bridge.execute("opalstack__apps", {"action": "delete", "id": "prod"})
    finally:
        bridge.close()
    assert is_error is True
    assert result["blocked"] is True
    assert "--dangerous" in result["error"]


def test_safe_mode_blocks_vibeshell_delete_by_tool_name(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), autopilot=False)

    class FakeMCP:
        def call_tool(self, name, arguments):
            raise AssertionError("fs_delete must not execute in SAFE mode")

    bridge.runtime["vibe_prod__fs_delete"] = (
        "vibe_prod", FakeMCP(), {"name": "fs_delete", "description": "delete file"}
    )
    try:
        result, is_error = bridge.execute("vibe_prod__fs_delete", {"path": "app.py"})
    finally:
        bridge.close()
    assert is_error is True
    assert result["blocked"] is True


def test_safe_shell_allows_tests_but_blocks_arbitrary_mutation():
    assert agent._shell_is_safe("pytest -q") is True
    assert agent._shell_is_safe("git status && git diff") is True
    assert agent._shell_is_safe("npm run build") is True
    assert agent._shell_is_safe("sed -i 's/a/b/' app.py") is False
    assert agent._shell_is_safe("python deploy.py") is False
    assert agent._shell_destruction_reason("git reset --hard HEAD") == "git reset --hard"
    assert agent._shell_destruction_reason("rm -rf ./src") == "recursive rm"


def test_journal_redacts_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    journal = agent.MutationJournal()
    journal.record("test", arguments={"token": "abc", "password": "def", "name": "ok"})
    raw = journal.path.read_text()
    assert "abc" not in raw
    assert "def" not in raw
    assert '"name": "ok"' in raw
    assert journal.path.stat().st_mode & 0o077 == 0


def test_no_opal_token_means_no_control_plane_spec(tmp_path, monkeypatch):
    monkeypatch.setenv("OPALSTACK_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("OPALSTACK_TOKEN", raising=False)
    s = SimpleNamespace(profile="default", data={"default": "default", "profiles": {}})
    assert agent._mcp_server_specs(s) == []


def test_dangerous_mode_requires_typed_confirmation(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), dangerous=True, work_mode="build")
    called = {"count": 0}

    class FakeMCP:
        def call_tool(self, name, arguments):
            called["count"] += 1
            return {"isError": False, "content": []}

    bridge.runtime["opalstack__apps"] = (
        "opalstack", FakeMCP(), {"name": "apps", "description": "apps"}
    )
    monkeypatch.setattr(agent.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(agent.click, "prompt", lambda *a, **kw: "wrong")
    try:
        result, is_error = bridge.execute("opalstack__apps", {"action": "delete", "id": "prod"})
    finally:
        bridge.close()
    assert is_error is True
    assert result["approved"] is False
    assert called["count"] == 0


def test_safe_mode_blocks_overwriting_existing_vibe_file(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), autopilot=True, work_mode="build")
    writes = []

    class FakeMCP:
        def call_tool(self, name, arguments):
            if name == "fs_read":
                return {"isError": False, "content": [{"type": "text", "text": "old code"}]}
            writes.append((name, arguments))
            return {"isError": False, "content": []}

    fake = FakeMCP()
    bridge.runtime["vibe_prod__fs_write"] = (
        "vibe_prod", fake, {"name": "fs_write", "description": "write"}
    )
    bridge.raw_runtime[("vibe_prod", "fs_read")] = (fake, {"name": "fs_read"})
    try:
        result, is_error = bridge.execute("vibe_prod__fs_write", {"path": "app.py", "content": "new"})
    finally:
        bridge.close()
    assert is_error is True
    assert result["blocked"] is True
    assert "fs_patch" in result["error"]
    assert writes == []


def test_mcp_http_client_bearer_init_and_tool_pagination(monkeypatch):
    client = agent.MCPHttpClient("https://mcp.example.test/mcp", "vibe-secret")
    seen = []

    class Resp:
        def __init__(self, payload=None, status=200, headers=None):
            self.status_code = status
            self._payload = payload
            self.headers = headers or {"content-type": "application/json"}
            self.text = ""
        def json(self):
            if self._payload is None:
                raise ValueError()
            return self._payload

    replies = iter([
        Resp({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}},
             headers={"content-type": "application/json", "mcp-session-id": "sess-1"}),
        Resp(None, status=202, headers={}),
        Resp({"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [{"name": "one"}], "nextCursor": "next"
        }}),
        Resp({"jsonrpc": "2.0", "id": 3, "result": {"tools": [{"name": "two"}]}}),
    ])

    def fake_post(url, **kwargs):
        seen.append((url, kwargs))
        return next(replies)

    monkeypatch.setattr(client.session, "post", fake_post)
    try:
        tools = client.list_tools()
    finally:
        client.close()
    assert [tool["name"] for tool in tools] == ["one", "two"]
    assert seen[0][1]["headers"]["Authorization"] == "Bearer vibe-secret"
    assert seen[0][1]["json"]["method"] == "initialize"
    assert seen[2][1]["headers"]["Mcp-Session-Id"] == "sess-1"
    assert seen[3][1]["json"]["params"] == {"cursor": "next"}


def test_mcp_http_client_reports_http_status_on_non_json_auth_failure(monkeypatch):
    client = agent.MCPHttpClient("https://mcp.example.test/mcp", "bad")

    class Resp:
        status_code = 401
        headers = {"content-type": "text/html"}
        text = "unauthorized"
        def json(self):
            raise ValueError()

    monkeypatch.setattr(client.session, "post", lambda *a, **kw: Resp())
    try:
        with pytest.raises(agent.AgentError) as exc:
            client.initialize()
    finally:
        client.close()
    assert "MCP HTTP 401" in exc.value.format_message()


def test_safe_vibe_delete_translates_to_trash_move(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), autopilot=True, work_mode="build")
    calls = []

    class FakeMCP:
        def call_tool(self, name, arguments):
            calls.append((name, arguments))
            return {"isError": False, "content": []}

    fake = FakeMCP()
    bridge.runtime["vibe_prod__fs_delete"] = (
        "vibe_prod", fake, {"name": "fs_delete", "description": "delete"}
    )
    bridge.raw_runtime[("vibe_prod", "fs_move")] = (fake, {"name": "fs_move"})
    monkeypatch.setattr(agent, "_approve", lambda *a, **kw: True)
    try:
        result, is_error = bridge.execute("vibe_prod__fs_delete", {"path": "~/apps/site/old.py", "recursive": False})
    finally:
        bridge.close()
    assert is_error is False
    assert calls[0][0] == "fs_move"
    assert calls[0][1]["from"] == "~/apps/site/old.py"
    assert calls[0][1]["overwrite"] is False
    assert calls[0][1]["mkdirs"] is True
    assert calls[0][1]["to"].startswith(".opal-trash/")
    assert calls[0][1]["to"].endswith("/apps/site/old.py")
    assert result["opal_safety"]["permanent_delete"] is False


def test_safe_fs_patch_forces_backup_and_blocks_delete_patch(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), autopilot=True, work_mode="build")
    calls = []

    class FakeMCP:
        def call_tool(self, name, arguments):
            calls.append((name, dict(arguments)))
            if name == "fs_read":
                return {"isError": False, "content": [{"type": "text", "text": "old"}]}
            return {"isError": False, "content": []}

    fake = FakeMCP()
    definition = {"name": "fs_patch", "description": "patch"}
    bridge.runtime["vibe_prod__fs_patch"] = ("vibe_prod", fake, definition)
    bridge.raw_runtime[("vibe_prod", "fs_read")] = (fake, {"name": "fs_read"})
    try:
        result, is_error = bridge.execute("vibe_prod__fs_patch", {
            "path": "app.py", "patches": [{"op": "replace_string", "search": "a", "replace": "b"}]
        })
        blocked, blocked_error = bridge.execute("vibe_prod__fs_patch", {
            "path": "app.py", "patches": [{"op": "delete", "start_line": 1, "end_line": 99}]
        })
    finally:
        bridge.close()
    assert is_error is False
    patch_call = next(args for name, args in calls if name == "fs_patch")
    assert patch_call["backup"] is True
    assert blocked_error is True
    assert blocked["blocked"] is True
    assert "line-delete" in blocked["error"]



def test_work_mode_defaults_and_tiers(monkeypatch):
    monkeypatch.delenv("OPAL_AGENT_MODE", raising=False)
    monkeypatch.delenv("OPAL_AGENT_TIER", raising=False)
    assert agent._resolve_work_mode(None) == "plan"
    assert agent._resolve_tier("plan", None) == ("normal", False)
    assert agent._resolve_tier("build", None) == ("heavy", False)
    assert agent._resolve_tier("ops", None) == ("normal", False)
    assert agent._resolve_tier("manage", None) == ("normal", False)


def test_plan_mode_blocks_mcp_mutation(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), work_mode="plan")

    class FakeMCP:
        def call_tool(self, name, arguments):
            raise AssertionError("PLAN mutation must not reach MCP")

    bridge.runtime["opalstack__apps"] = (
        "opalstack", FakeMCP(), {"name": "apps", "description": "apps"}
    )
    try:
        result, is_error = bridge.execute("opalstack__apps", {"action": "create", "name": "nope"})
    finally:
        bridge.close()
    assert is_error is True
    assert result["blocked"] is True
    assert "PLAN mode is read-only" in result["error"]


def test_manage_mode_blocks_mcp_mutation(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), work_mode="manage")

    class FakeMCP:
        def call_tool(self, name, arguments):
            raise AssertionError("MANAGE mutation must not reach MCP")

    bridge.runtime["opalstack__sites"] = (
        "opalstack", FakeMCP(), {"name": "sites", "description": "sites"}
    )
    try:
        result, is_error = bridge.execute("opalstack__sites", {"action": "update", "id": "x"})
    finally:
        bridge.close()
    assert is_error is True
    assert result["blocked"] is True
    assert "MANAGE mode is read-only" in result["error"]


def test_plan_local_shell_allows_observation_but_not_build(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.OpenAIAgentSession(s, "key", work_mode="plan")
    try:
        monkeypatch.setattr(agent, "_execute_function", lambda *a, **kw: {"ok": True})
        ok, err = session._execute_tool({"name": "ssh_exec", "arguments": json.dumps({
            "user": "u", "command": "git status", "cwd": "~", "timeout": 30
        })})
        blocked, blocked_err = session._execute_tool({"name": "ssh_exec", "arguments": json.dumps({
            "user": "u", "command": "pytest -q", "cwd": "~", "timeout": 30
        })})
    finally:
        session.close()
    assert err is False and ok["ok"] is True
    assert blocked_err is True and blocked["blocked"] is True


def test_mode_switch_changes_auto_tier(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.OpenAIAgentSession(s, "key", work_mode="plan")
    try:
        assert session.tier == "normal"
        session.set_mode("build")
        assert session.tier == "heavy"
        assert session.model == agent.OPENAI_MODEL_PRESETS["deep"][0]
        session.set_tier("normal", locked=True)
        session.set_mode("ops")
        assert session.tier == "normal"
        session.set_mode("build")
        assert session.tier == "normal"  # explicit user override survives mode switches
    finally:
        session.close()


def test_lazy_tool_search_activates_matching_schema(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)

    class FakeMCP:
        def __init__(self, url, token): pass
        def list_tools(self):
            return [
                {"name": "apps", "description": "Manage applications", "inputSchema": {"type": "object", "properties": {}}},
                {"name": "mail", "description": "Manage email addresses", "inputSchema": {"type": "object", "properties": {}}},
            ]
        def close(self): pass

    monkeypatch.setattr(agent, "MCPHttpClient", FakeMCP)
    session = agent.OpenAIAgentSession(s, "open-key")
    try:
        assert len(session.active_tools) == 0
        result, err = session._execute_tool({
            "name": "opal_tool_search",
            "arguments": json.dumps({"query": "applications", "limit": 5}),
        })
        assert err is False
        assert "opalstack__apps" in session.active_tools
        assert result["tools"][0]["name"] == "opalstack__apps"
    finally:
        session.close()


def test_turn_usage_tracks_cached_tokens(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    session = agent.OpenAIAgentSession(s, "open-key")
    responses = iter([{
        "id": "r1",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": "ok"}]}],
        "usage": {"input_tokens": 100, "output_tokens": 4, "input_tokens_details": {"cached_tokens": 80}},
    }])
    monkeypatch.setattr(session.client, "create", lambda payload: next(responses))
    try:
        assert session.turn("hello") == "ok"
        assert session.last_input == 100
        assert session.last_cached == 80
        assert session.last_output == 4
    finally:
        session.close()


def test_shell_history_path_uses_private_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    path = agent._shell_history_path()
    assert path == tmp_path / "opalstack" / "history"
    assert path.parent.exists()


def test_transcript_save_and_render(tmp_path):
    transcript = agent.SessionTranscript()
    transcript.add("user", "hello")
    transcript.add("opal", "world")
    out = transcript.save(str(tmp_path / "session.txt"))
    text = out.read_text()
    assert "[USER]" in text and "hello" in text
    assert "[OPAL]" in text and "world" in text


def test_platform_context_bakes_in_two_surface_topology_and_ready_gate():
    text = agent.PLATFORM_CONTEXT
    assert "classic Opalstack API/MCP" in text
    assert "VibeShell" in text
    assert "DOMAIN is a DNS name" in text
    assert "SITE is web-server configuration" in text
    assert "wait until READY" in text
    assert "NOTICE LOG" in text
    assert "vibeshell_adopt" in text
    assert "SSH is bootstrap/recovery" in text or "SSH is bootstrap" in text


def test_wait_ready_object_polls_until_ready(monkeypatch):
    calls = []
    replies = iter([
        {"id": "abc", "name": "demo", "ready": False, "status": "STARTING"},
        {"id": "abc", "name": "demo", "ready": True, "status": "READY"},
    ])

    class Manager:
        def read(self, ident):
            calls.append(ident)
            return next(replies)

    class State:
        wait_timeout = 5
        def manager(self, resource):
            assert resource == "apps"
            return Manager()

    monkeypatch.setattr(agent.time, "sleep", lambda _: None)
    result = agent._wait_ready_object(State(), "application", "abc", 5)
    assert result["ready"] is True
    assert result["status"] == "READY"
    assert calls == ["abc", "abc"]


def test_vibeshell_status_reports_ready_exec(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_resolve_user", lambda *_: {"id": "u1", "name": "alice"})
    monkeypatch.setattr(agent, "_control_vibeshell_candidates", lambda *_: [])
    agent.save_vibe(s, agent.VibeEndpoint("alice", "https://v.example/", "secret", "alice", "vibeshell", "~/apps", True))

    class FakeMCP:
        def __init__(self, *a, **kw): pass
        def list_tools(self):
            return [{"name": "fs_read"}, {"name": "fs_tail"}, {"name": "shell_run"}]
        def close(self): pass

    monkeypatch.setattr(agent, "MCPHttpClient", FakeMCP)
    result = agent.vibeshell_status(s, "alice")
    assert result["state"] == "READY_EXEC"
    assert result["exec_enabled"] is True
    assert "shell_run" in result["tools"]
    assert "secret" not in json.dumps(result)


def test_ssh_refuses_normal_path_when_vibeshell_ready_exec(monkeypatch):
    s = SimpleNamespace()
    monkeypatch.setattr(agent, "vibeshell_status", lambda *_: {"state": "READY_EXEC", "endpoint": "https://v.example/"})
    result = agent.ssh_exec(
        s,
        {"user": "alice", "command": "tail -n 20 ~/logs/x", "cwd": "~", "timeout": 30, "purpose": "recovery"},
        Console(file=None, force_terminal=False),
        autopilot=False,
    )
    assert result["blocked"] is True
    assert "shell_run" in result["error"]


def test_control_plane_mutation_waits_for_ready(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), autopilot=True, work_mode="build")
    ident = "123e4567-e89b-42d3-a456-426614174000"
    waited = []

    class FakeMCP:
        def call_tool(self, name, arguments):
            return {"content": [{"type": "text", "text": json.dumps({"id": ident, "ready": False})}]}

    monkeypatch.setattr(agent, "_wait_ready_object", lambda state, resource, obj_id, timeout: waited.append((resource, obj_id)) or {"ok": True, "resource": resource, "id": obj_id, "ready": True, "status": "READY"})
    bridge.runtime["opalstack__mcp_opalstack_application"] = (
        "opalstack", FakeMCP(), {"name": "mcp_opalstack_application", "description": "applications"}
    )
    try:
        result, err = bridge.execute("opalstack__mcp_opalstack_application", {"action": "create", "name": "demo"})
    finally:
        bridge.close()
    assert err is False
    assert waited == [("apps", ident)]
    assert result["opal_readiness"][0]["status"] == "READY"


def test_log_request_routes_toward_control_and_vibeshell(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)

    class FakeMCP:
        def __init__(self, url, token):
            self.url = url
        def list_tools(self):
            if "my.opalstack" in self.url:
                return [
                    {"name": "mcp_opalstack_application", "description": "applications", "inputSchema": {"type": "object", "properties": {}}},
                    {"name": "mcp_opalstack_osuser", "description": "shell users", "inputSchema": {"type": "object", "properties": {}}},
                    {"name": "mcp_opalstack_site", "description": "sites", "inputSchema": {"type": "object", "properties": {}}},
                ]
            return [
                {"name": "fs_tail", "description": "tail logs", "inputSchema": {"type": "object", "properties": {}}},
                {"name": "shell_run", "description": "run command", "inputSchema": {"type": "object", "properties": {}}},
            ]
        def close(self): pass

    agent.save_vibe(s, agent.VibeEndpoint("alice", "https://v.example/", "vibe-secret", "alice", "vibeshell", "~/apps", True))
    monkeypatch.setattr(agent, "MCPHttpClient", FakeMCP)
    bridge = agent.LocalMCPBridge(s, Console(file=None, force_terminal=False), work_mode="ops")
    try:
        names = bridge.search_tool_names("check the application logs and running process", 8)
    finally:
        bridge.close()
    joined = " ".join(names)
    assert "application" in joined
    assert "osuser" in joined
    assert "fs_tail" in joined or "shell_run" in joined


def test_ollama_provider_can_run_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPAL_AGENT_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.setattr(agent, "_ollama_available", lambda: True)
    assert agent._resolve_provider("ollama") == ("ollama", "")


def test_auto_provider_selects_ollama_when_only_local_provider(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPAL_AGENT_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.setattr(agent, "_ollama_available", lambda: True)
    assert agent._resolve_provider() == ("ollama", "")


def test_ollama_payload_uses_chat_function_tools(tmp_path, monkeypatch):
    s = state(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "_mcp_server_specs", lambda state: [])
    monkeypatch.setattr(agent, "_resolve_ollama_model", lambda tier: "qwen3:8b")
    session = agent.OllamaAgentSession(s, model="qwen3:8b")
    try:
        payload = session._payload()
        assert payload["model"] == "qwen3:8b"
        assert payload["messages"][0]["role"] == "system"
        assert payload["tools"]
        first = payload["tools"][0]
        assert first["type"] == "function"
        assert "function" in first
        assert "name" in first["function"]
    finally:
        session.close()


def test_remote_ollama_http_is_rejected(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://example.com:11434/v1")
    with pytest.raises(agent.AgentError):
        agent._ollama_base_url()

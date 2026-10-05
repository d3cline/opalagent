import json
import os
from unittest.mock import Mock

import click
from click.testing import CliRunner
import pytest

from opalstack_cli import config
from opalstack_cli.cli import cli
from opalstack_cli.client import Client, APIError
from opalstack_cli.output import redact
from opalstack_cli.resources import MANAGERS, RESOURCES

ID = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def run(monkeypatch, tmp_path):
    monkeypatch.setenv("OPALSTACK_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("OPALSTACK_TOKEN", "test-token")
    return CliRunner().invoke


@pytest.fixture
def backend(monkeypatch):
    calls = []
    replies = []

    def request(self, path, method, dataObj, ensure_status=None):
        calls.append((path, method, dataObj))
        if not replies:
            raise AssertionError(f"Unexpected API request: {method} {path}")
        reply = replies.pop(0)
        return Mock(status_code=200), reply

    monkeypatch.setattr(Client, "request", request)
    return calls, replies


def test_help_offline(run, monkeypatch):
    monkeypatch.delenv("OPALSTACK_TOKEN")
    result = run(cli, ["--help"])
    assert result.exit_code == 0
    assert "postgres-dbs" in result.output


@pytest.mark.parametrize("resource", RESOURCES)
def test_capabilities_match_sdk(resource):
    import opalstack
    manager = getattr(opalstack.Api("test"), MANAGERS.get(resource, resource))
    methods = type(manager).__dict__
    for action in RESOURCES[resource].split():
        method = {"list": "list_all", "get": "read"}.get(action, action)
        assert method in methods


def test_unsupported_commands(run):
    for args in (["servers", "create"], ["domains", "update"]):
        result = run(cli, args)
        assert result.exit_code == 2


def test_list_json_and_redaction(run, backend):
    calls, replies = backend
    replies.append([{"id": ID, "name": "app", "default_password": "supersecret"}])
    result = run(cli, ["-o", "json", "apps", "list"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)[0]["default_password"] == "[redacted]"
    assert calls == [("/app/list/", "GET", None)]


def test_server_flatten_filter(run, backend):
    calls, replies = backend
    replies.append({"web_servers": [{"id": ID, "hostname": "opal1.opalstack.com"}], "imap_servers": []})
    result = run(cli, ["-o", "json", "servers", "list", "--filter", "_group=web_servers"])
    assert json.loads(result.output)[0]["_group"] == "web_servers"


def test_embed_and_filter(run, backend):
    calls, replies = backend
    replies.append([{"id": ID, "server": {"hostname": "opal1"}}, {"id": OTHER, "server": {"hostname": "opal2"}}])
    result = run(cli, ["-o", "json", "users", "list", "--embed", "server", "--filter", "server.hostname=opal1"])
    assert result.exit_code == 0
    assert len(json.loads(result.output)) == 1
    assert calls[0][0] == "/osuser/list/?embed=server"


def test_dry_run_no_token_or_http(run, monkeypatch, backend):
    monkeypatch.delenv("OPALSTACK_TOKEN")
    result = run(cli, ["-o", "json", "domains", "create", "--name", "example.com", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["items"] == [{"name": "example.com"}]
    assert backend[0] == []


def test_related_name_create(run, backend):
    calls, replies = backend
    replies.extend([[{"id": ID, "name": "web"}], [{"id": OTHER, "name": "app"}]])
    result = run(cli, ["-o", "json", "apps", "create", "--name", "app", "--osuser", "web", "--type", "STA", "--yes", "--no-wait"])
    assert result.exit_code == 0, result.output
    assert calls[-1] == ("/app/create/", "POST", [{"name": "app", "osuser": ID, "type": "STA"}])


def test_update_only_supplied_fields(run, backend):
    calls, replies = backend
    replies.extend([[{"id": ID, "name": "old", "type": "STA"}], [{"id": ID, "name": "new"}]])
    result = run(cli, ["apps", "update", "old", "--name", "new", "--yes", "--no-wait"])
    assert result.exit_code == 0, result.output
    assert calls[-1][2] == [{"id": ID, "name": "new"}]


def test_conflicting_selector_id(run, backend):
    calls, replies = backend
    replies.append({"id": ID, "name": "a"})
    result = run(cli, ["apps", "update", ID, "--json", json.dumps({"id": OTHER, "name": "b"}), "--yes"])
    assert result.exit_code == 2
    assert all(c[1] == "GET" for c in calls)


def test_batch_stdin(run, backend):
    calls, replies = backend
    replies.append([{"id": ID, "name": "one.com"}, {"id": OTHER, "name": "two.com"}])
    result = run(cli, ["-o", "json", "domains", "create", "--file", "-", "--yes", "--no-wait"],
                 input='[{"name":"one.com"},{"name":"two.com"}]')
    assert result.exit_code == 0, result.output
    assert len(calls[0][2]) == 2


@pytest.mark.parametrize("arguments", [
    ["domains", "create", "--json", "[]"],
    ["domains", "create", "--json", "{bad"],
    ["domains", "create", "--json", '[{"name":"a"}]', "--name", "b"],
    ["apps", "update", "--name", "a"],
    ["apps", "create", "--set-json", "thing=notjson"],
    ["apps", "create", "--set", "=bad"],
])
def test_invalid_payload_no_writes(run, backend, arguments):
    result = run(cli, arguments + ["--yes"])
    assert result.exit_code == 2, result.output
    assert backend[0] == []


def test_write_requires_yes_noninteractive(run, backend):
    result = run(cli, ["domains", "create", "--name", "example.com"])
    assert result.exit_code == 1
    assert "--yes" in result.output
    assert backend[0] == []


def test_ambiguous_delete_has_no_write(run, backend):
    calls, replies = backend
    replies.append([{"id": ID, "name": "same"}, {"id": OTHER, "name": "same"}])
    result = run(cli, ["apps", "delete", "same", "--yes"])
    assert result.exit_code == 1
    assert "Ambiguous" in result.output
    assert len(calls) == 1


def test_delete_resolves_all_before_writing(run, backend):
    calls, replies = backend
    replies.extend([[{"id": ID, "name": "one"}], []])
    result = run(cli, ["apps", "delete", "one", "missing", "--yes"])
    assert result.exit_code == 1
    assert all(c[1] == "GET" for c in calls)


def test_token_delete_uses_key(run, backend):
    calls, replies = backend
    replies.extend([[{"key": "a" * 40, "name": "old"}], {}])
    result = run(cli, ["-o", "json", "tokens", "delete", "old", "--yes"])
    assert result.exit_code == 0, result.output
    assert calls[-1][2] == [{"key": "a" * 40}]
    assert "a" * 40 not in result.output


def test_no_wait_skips_polling(run, backend):
    calls, replies = backend
    replies.append([{"id": ID, "ready": False}])
    result = run(cli, ["apps", "create", "--name", "a", "--no-wait", "--yes"])
    assert result.exit_code == 0
    assert len(calls) == 1


def test_default_wait_polls_real_sdk(run, backend):
    calls, replies = backend
    replies.extend([[{"id": ID, "ready": False}], {"id": ID, "ready": True}])
    result = run(cli, ["apps", "create", "--name", "a", "--yes"])
    assert result.exit_code == 0, result.output
    assert calls[-1][0] == f"/app/read/{ID}"


def test_secret_output_explicit(run, backend):
    backend[1].append([{"password": "fresh-secret"}])
    result = run(cli, ["--show-secrets", "-o", "json", "users", "list"])
    assert json.loads(result.output)[0]["password"] == "fresh-secret"


def test_redaction_nested():
    value = {"routes": [{"private_key": "secret", "value": "env-secret"}], "name": "fine"}
    assert "secret" not in json.dumps(redact(value))


def test_usage(run, backend):
    backend[1].append({"usage": 12})
    result = run(cli, ["-o", "json", "usage", "mail"])
    assert result.exit_code == 0
    assert backend[0][0][0] == "/usage/mail/latest/"


def test_snapshot(run, backend):
    backend[1].append([{"id": ID}])
    result = run(cli, ["snapshot", "--resource", "apps"])
    assert result.exit_code == 0
    assert json.loads(result.output)["resources"]["apps"] == [{"id": ID}]


def test_ssh_print_and_option_injection(run, backend):
    backend[1].append([{"id": ID, "name": "web", "server": {"hostname": "opal1.opalstack.com"}}])
    result = run(cli, ["ssh", "web", "--print"])
    assert result.exit_code == 0, result.output
    assert result.output.strip() == "ssh -p 22 web@opal1.opalstack.com"
    backend[1].append([{"id": ID, "name": "web", "server": {"hostname": "-oProxyCommand=evil"}}])
    result = run(cli, ["ssh", "web", "--print"])
    assert result.exit_code == 1


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion(run, shell):
    result = run(cli, ["completion", shell])
    assert result.exit_code == 0, result.output
    assert "_OPALAGENT_COMPLETE" in result.output


def test_login_permissions_and_env_precedence(run, backend):
    backend[1].append([{"id": ID}])
    result = run(cli, ["--profile", "production", "auth", "login", "--token-stdin"], input="new-token\n")
    assert result.exit_code == 0, result.output
    data = config.load()
    assert data["default"] == "production"
    assert data["profiles"]["production"]["token"] == "new-token"
    assert config.get_token("production", data) == "test-token"
    assert config.config_path().stat().st_mode & 0o777 == 0o600


def test_config_rejects_open_permissions(run):
    config.save({"profiles": {}, "default": "default"})
    os.chmod(config.config_path(), 0o644)
    result = run(cli, ["profiles", "list"])
    assert result.exit_code == 1
    assert "chmod 600" in result.output


def test_alias(run, backend):
    backend[1].append([])
    assert run(cli, ["osusers", "list"]).exit_code == 0
    assert backend[0][0][0] == "/osuser/list/"


def test_transport_status_and_secret_suppression(monkeypatch):
    client = Client("secret")
    response = Mock(status_code=400)
    response.json.return_value = {"error": "secret-value"}
    client.session.request = Mock(return_value=response)
    with pytest.raises(APIError) as exc:
        client.request("/app/list/", "GET", None)
    assert "secret-value" not in str(exc.value)
    assert "400" in str(exc.value)
    assert client.session.request.call_args.kwargs["allow_redirects"] is False
    assert client.session.request.call_args.kwargs["timeout"] == 30


def test_post_not_retried(monkeypatch):
    import requests
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.request.side_effect = requests.Timeout("secret")
    client = Client("secret")
    monkeypatch.setattr(requests, "Session", lambda: session)
    with pytest.raises(click.ClickException, match="may have reached"):
        client.request("/app/create/", "POST", [{"password": "secret"}])
    assert session.request.call_count == 1


def test_get_retry_configuration():
    client = Client("secret")
    retry = client.session.get_adapter("https://").max_retries
    assert retry.allowed_methods == frozenset({"GET"})
    assert retry.total == 2


def test_wait_deleted_and_timeout(monkeypatch):
    client = Client("secret", wait_timeout=1)
    client.request = Mock(return_value=(Mock(status_code=404), None))
    client.wait_deleted("app", [ID])
    client.request = Mock(return_value=(Mock(status_code=200), {"ready": False}))
    monkeypatch.setattr("opalstack_cli.client.time.sleep", lambda _: None)
    with pytest.raises(click.ClickException, match="may still finish"):
        client.wait_ready("app", [ID], tries=1)


def test_confirmation_preview_stays_on_stderr(monkeypatch, capsys):
    import sys
    from opalstack_cli.cli import confirm
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("opalstack_cli.cli.click.confirm", lambda *a, **kw: True)
    confirm("create", "domains", [{"name": "example.com"}], False)
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == [{"name": "example.com"}]


@pytest.mark.parametrize("resource", RESOURCES)
def test_actual_transport_get_routes(run, monkeypatch, resource):
    import requests
    calls = []

    def request(self, method, url, **kwargs):
        calls.append((method, url, kwargs))
        response = Mock(status_code=200)
        response.json.return_value = []
        return response

    monkeypatch.setattr(requests.Session, "request", request)
    result = run(cli, ["-o", "json", resource, "list"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == []
    manager = getattr(Client("test"), MANAGERS.get(resource, resource))
    assert calls[0][1].endswith(f"/{manager.model_name}/list/")
    assert calls[0][2]["headers"]["Authorization"] == "Token test-token"


def test_actual_transport_post_payload(run, monkeypatch):
    import requests
    calls = []

    def request(self, method, url, **kwargs):
        calls.append((method, url, kwargs))
        response = Mock(status_code=200)
        response.json.return_value = [{"id": ID, "name": "example.com"}]
        return response

    monkeypatch.setattr(requests.Session, "request", request)
    result = run(cli, ["domains", "create", "--name", "example.com", "--yes", "--no-wait"])
    assert result.exit_code == 0, result.output
    assert calls[0][0] == "POST"
    assert calls[0][1].endswith("/domain/create/")
    assert calls[0][2]["json"] == [{"name": "example.com"}]
    assert calls[0][2]["timeout"] == 30.0


def test_provisioning_disappearance():
    client = Client("test")
    client.request = Mock(return_value=(Mock(status_code=404), None))
    with pytest.raises(click.ClickException, match="disappeared"):
        client.wait_ready("app", [ID])


def test_changing_storage_requires_cleanup(run, backend):
    config.save({"default": "default", "profiles": {"default": {"storage": "keyring"}}})
    result = run(cli, ["auth", "login", "--storage", "file", "--token-stdin"], input="new-token")
    assert result.exit_code == 1
    assert "Log out" in result.output
    assert backend[0] == []

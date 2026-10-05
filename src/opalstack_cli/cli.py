"""Discoverable resource commands and operator workflows."""
import json
import logging
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from uuid import UUID

import click

from . import __version__, config
from .client import Client
from .output import display, field, redact
from .resources import ALIASES, FIELDS, MANAGERS, RELATIONS, RESOURCES


class Root(click.Group):
    def get_command(self, ctx, cmd_name):
        return super().get_command(ctx, ALIASES.get(cmd_name, cmd_name))


class State:
    def __init__(self, profile, output, timeout, wait_timeout, show_secrets):
        self.data = config.load()
        self.profile = profile or self.data.get("default", "default")
        self.output = output
        self.timeout = timeout
        self.wait_timeout = wait_timeout
        self.show_secrets = show_secrets
        self._api = None

    @property
    def api(self):
        if self._api is None:
            self._api = Client(config.get_token(self.profile, self.data), self.timeout, self.wait_timeout)
        return self._api

    def manager(self, resource):
        return getattr(self.api, MANAGERS.get(resource, resource))

    def emit(self, value, columns=None):
        display(value, self.output, columns, self.show_secrets)


@click.group(cls=Root, invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__)
@click.option("--profile", "-p", envvar="OPALSTACK_PROFILE", help="Named account profile.")
@click.option("--output", "-o", type=click.Choice(["table", "json", "jsonl", "ids"]),
              default="table", show_default=True, envvar="OPALSTACK_OUTPUT")
@click.option("--timeout", type=click.FloatRange(min=0.1), default=30.0, show_default=True,
              help="Timeout per HTTP request, in seconds.")
@click.option("--wait-timeout", type=click.FloatRange(min=0.1), default=300.0, show_default=True,
              help="Provisioning polling budget; an in-flight HTTP request may run past it.")
@click.option("--show-secrets", is_flag=True, help="Reveal passwords/keys in results. Treat output as sensitive.")
@click.pass_context
def cli(ctx, **kwargs):
    """Opalstack infrastructure from your terminal.

    Put global options before the resource. Use RESOURCE --help to explore.
    Writes accept friendly flags, --set FIELD=VALUE, or JSON files/stdin.
    """
    # The SDK logs request payloads. Keep its logging disabled even in embedded use.
    logging.getLogger("opalstack").setLevel(logging.CRITICAL)
    ctx.obj = State(**kwargs)
    ctx.call_on_close(lambda: ctx.obj._api.session.close() if ctx.obj._api is not None else None)

    # Interactive default: `opalagent` is the agent console.  Piped/non-interactive
    # invocation remains deterministic and prints help instead of consuming stdin.
    if ctx.invoked_subcommand is None:
        if not sys.stdin.isatty():
            click.echo(ctx.get_help())
            return
        from .agent import repl
        repl(ctx.obj)


def rows(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Servers are returned as web_servers, imap_servers, etc.
        if all(isinstance(v, list) for v in data.values()):
            return [dict(row, _group=group) for group, values in data.items() for row in values]
        return [data]
    raise click.ClickException("Unexpected resource response shape.")


def is_uuid(text):
    try:
        UUID(text)
        return True
    except (ValueError, TypeError):
        return False


def resolve(state, resource, selector, embed=()):
    manager = state.manager(resource)
    if is_uuid(selector) or (resource == "tokens" and re.fullmatch(r"[a-fA-F0-9]{40}", selector)):
        return manager.read(selector, embed=list(embed))
    candidates = rows(manager.list_all(embed=list(embed)))
    matches = [r for r in candidates if selector in
               [str(r.get(k, "")) for k in (manager.primary_key, "name", "hostname", "source", "address", "ip")]]
    # Deduplicate server IDs shared between server roles.
    matches = list({r[manager.primary_key]: r for r in matches}.values())
    if len(matches) != 1:
        if not matches:
            raise click.ClickException(f"No {resource} resource matches that name or ID.")
        raise click.ClickException(f"Ambiguous {resource} name ({len(matches)} matches). Use an exact ID.")
    return matches[0]


def parse_pairs(pairs, typed=False):
    result = {}
    for item in pairs:
        if "=" not in item:
            raise click.BadParameter("Expected FIELD=VALUE.")
        key, value = item.split("=", 1)
        if not key or key in result:
            raise click.BadParameter("Field names must be nonempty and unique.")
        if typed:
            try:
                value = json.loads(value)
            except ValueError as exc:
                raise click.BadParameter(f"Field {key} requires valid JSON.") from exc
        result[key] = value
    return result


def payload(file, json_text, sets, typed_sets, secret_fields, flags):
    if file and json_text is not None:
        raise click.UsageError("Choose --file or --json, not both.")
    try:
        source = file.read() if file else json_text
        data = json.loads(source) if source is not None else {}
    except ValueError as exc:
        raise click.BadParameter("Input is not valid JSON.") from exc
    extra = parse_pairs(sets)
    typed = parse_pairs(typed_sets, typed=True)
    if set(extra) & set(typed):
        raise click.UsageError("A field cannot appear in both --set and --set-json.")
    extra.update(typed)
    for name in secret_fields:
        if not sys.stdin.isatty():
            raise click.ClickException("Secret prompts need a terminal; use a protected --file in automation.")
        extra[name] = click.prompt(name, hide_input=True, confirmation_prompt=True)
    for key, value in flags.items():
        if value is not None:
            if key in extra:
                raise click.UsageError(f"Field {key} was supplied more than once.")
            extra[key] = value
    if isinstance(data, list):
        if extra:
            raise click.UsageError("Batch arrays cannot be combined with per-item flags.")
        items = data
    elif isinstance(data, dict):
        data.update(extra)
        items = [data]
    else:
        raise click.BadParameter("Expected a JSON object or array of objects.")
    if not items or any(not isinstance(i, dict) or not i for i in items):
        raise click.BadParameter("Provide at least one nonempty object.")
    return items


def confirm(action, resource, items, yes):
    if yes:
        return
    if not sys.stdin.isatty():
        raise click.ClickException("Noninteractive changes require --yes. Review with --dry-run first.")
    display(redact(items), "json", stderr=True)
    click.confirm(f"{action.title()} {len(items)} {resource} item(s)?", abort=True, err=True)


def write_options(fn):
    options = [
        click.option("--file", "file", type=click.File("r"), help="JSON object/array; '-' reads stdin."),
        click.option("--json", "json_text", help="Inline JSON object/array."),
        click.option("--set", "sets", multiple=True, metavar="FIELD=TEXT", help="Set a string field; repeatable."),
        click.option("--set-json", "typed_sets", multiple=True, metavar="FIELD=JSON", help="Set numbers, booleans, arrays or objects."),
        click.option("--secret", "secret_fields", multiple=True, metavar="FIELD", help="Prompt for a sensitive field without echo."),
        click.option("--dry-run", is_flag=True, help="Print the resolved request without writing."),
        click.option("--yes", "-y", is_flag=True, help="Approve the write without prompting."),
        click.option("--wait/--no-wait", default=True, help="Wait for provisioning (bounded by --wait-timeout)."),
    ]
    for option in reversed(options):
        fn = option(fn)
    return fn


def make_list(resource):
    @click.command("list")
    @click.option("--embed", multiple=True, help="Embed a related API field; repeatable.")
    @click.option("--filter", "filters", multiple=True, metavar="FIELD=VALUE", help="Exact client-side filter; dot paths supported.")
    @click.option("--sort", "sort_key", help="Client-side sort by field/dot path.")
    @click.option("--reverse", is_flag=True)
    @click.option("--limit", type=click.IntRange(min=1), help="Limit displayed results (fetches the complete list).")
    @click.option("--columns", help="Comma-separated table columns, including dot paths.")
    @click.pass_obj
    def command(state, embed, filters, sort_key, reverse, limit, columns):
        """List resources, with optional filtering and sorting."""
        data = rows(state.manager(resource).list_all(embed=list(embed)))
        for key, value in parse_pairs(filters).items():
            data = [r for r in data if str(field(r, key)).lower() == value.lower()]
        if sort_key:
            data.sort(key=lambda r: (field(r, sort_key) is None, str(field(r, sort_key))), reverse=reverse)
        state.emit(data[:limit] if limit else data, columns.split(",") if columns else None)
    return command


def make_get(resource):
    @click.command("get")
    @click.argument("selector")
    @click.option("--embed", multiple=True)
    @click.pass_obj
    def command(state, selector, embed):
        """Read one resource by exact name or ID; ambiguous names are rejected."""
        result = resolve(state, resource, selector, embed)
        # Name lookup returns list representation; fetch full read representation.
        if not is_uuid(selector):
            result = state.manager(resource).read(result[state.manager(resource).primary_key], embed=list(embed))
        state.emit(result)
    return command


def make_write(resource, action):
    @click.pass_obj
    def command(state, file, json_text, sets, typed_sets, secret_fields, dry_run, yes, wait,
                selector=None, **flags):
        items = payload(file, json_text, sets, typed_sets, secret_fields, flags)
        # Only ergonomic relation flags resolve names; raw JSON stays exact.
        for key in flags:
            if flags[key] is not None and key in RELATIONS:
                items[0][key] = resolve(state, RELATIONS[key], flags[key])["id"]
        pk = "key" if resource == "tokens" else "id"
        if selector:
            if len(items) != 1:
                raise click.UsageError("A selector can only be combined with a single update object.")
            resolved = resolve(state, resource, selector)[pk]
            if pk in items[0] and items[0][pk] != resolved:
                raise click.UsageError("Payload ID conflicts with the selected resource.")
            items[0][pk] = resolved
        if action == "update" and any(not isinstance(i.get(pk), str) or not i[pk] for i in items):
            raise click.UsageError(f"Every update needs {pk}, or supply a resource selector.")
        if dry_run:
            state.emit({"action": action, "resource": resource, "items": items, "wait": wait})
            return
        confirm(action, resource, items, yes)
        state.emit(getattr(state.manager(resource), action)(items, wait=wait))
    command.__doc__ = f"{action.title()} resources. JSON field validation is performed by the API."
    command = write_options(command)
    for name in reversed(FIELDS.get(resource, [])):
        command = click.option("--" + name.replace("_", "-"), name,
                               type=int if name in {"ttl", "priority"} else str,
                               help="Related name/ID." if name in RELATIONS else f"API {name} field.")(command)
    if action == "update":
        command = click.argument("selector", required=False)(command)
    return click.command(action)(command)


def make_delete(resource):
    @click.command("delete")
    @click.argument("selectors", nargs=-1, required=True)
    @click.option("--yes", "-y", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--wait/--no-wait", default=True)
    @click.pass_obj
    def command(state, selectors, yes, dry_run, wait):
        """Delete explicitly selected resources. No wildcard or implicit cascade."""
        manager = state.manager(resource)
        items = [resolve(state, resource, selector) for selector in selectors]
        items = list({r[manager.primary_key]: r for r in items}.values())
        if dry_run:
            state.emit({"action": "delete", "resource": resource, "items": items})
            return
        confirm("delete", resource, items, yes)
        manager.delete(items, wait=wait)
        state.emit({"action": "delete", "submitted": True, "waited": wait,
                    "items": [{manager.primary_key: i[manager.primary_key]} for i in items]})
    return command


for resource, capabilities in RESOURCES.items():
    group = click.Group(resource, help=f"Manage {resource}; SDK manager: {MANAGERS.get(resource, resource)}.")
    for action in capabilities.split():
        factory = {"list": make_list, "get": make_get, "delete": make_delete}.get(action)
        group.add_command(factory(resource) if factory else make_write(resource, action))
    cli.add_command(group)


@cli.group()
def auth():
    """Log in, inspect credentials, or remove local credentials."""


@auth.command("login")
@click.option("--storage", type=click.Choice(["file", "keyring"]), default="file", show_default=True,
              help="File uses owner-only permissions; keyring requires the extra.")
@click.option("--token-stdin", is_flag=True, help="Read token from stdin instead of a hidden prompt.")
@click.pass_obj
def login(state, storage, token_stdin):
    """Validate a token with a read-only request, then save it to the selected profile."""
    existing = state.data["profiles"].get(state.profile)
    if existing and existing.get("storage", "file") != storage:
        raise click.ClickException(
            "Log out of this profile before changing credential storage, so no old credential is left behind."
        )
    if not token_stdin and not sys.stdin.isatty():
        raise click.ClickException("Use --token-stdin in noninteractive sessions.")
    token = sys.stdin.read().strip() if token_stdin else click.prompt("Vibe MCP/API token", hide_input=True).strip()
    if not token or any(c.isspace() for c in token):
        raise click.ClickException("Token must be a nonempty single value.")
    client = Client(token, state.timeout, state.wait_timeout)
    try:
        client.accounts.list_all()
    finally:
        client.session.close()
    if storage == "keyring":
        try:
            config.keyring_module().set_password("opalagent", state.profile, token)
        except click.ClickException:
            raise
        except Exception as exc:
            raise click.ClickException("Could not save to the keyring; no file fallback was used.") from exc
        entry = {"storage": "keyring"}
    else:
        entry = {"storage": "file", "token": token}
    state.data["profiles"][state.profile] = entry
    state.data.setdefault("default", state.profile)
    if state.data["default"] not in state.data["profiles"]:
        state.data["default"] = state.profile
    config.save(state.data)
    state.emit({"profile": state.profile, "authenticated": True, "storage": storage})


@auth.command("status")
@click.pass_obj
def auth_status(state):
    """Validate the active token without displaying it."""
    state.api.accounts.list_all()
    state.emit({"profile": state.profile, "authenticated": True,
                "source": "environment" if os.environ.get("OPALSTACK_TOKEN") else
                state.data["profiles"].get(state.profile, {}).get("storage", "file")})


@auth.command("mcp-status")
@click.pass_obj
def auth_mcp_status(state):
    """Initialize Opalstack Vibe MCP locally and report its discovered tool surface."""
    from .agent import MCPHttpClient, OPALSTACK_MCP_URL

    client = MCPHttpClient(OPALSTACK_MCP_URL, config.get_token(state.profile, state.data), timeout=state.timeout)
    try:
        tools = client.list_tools()
    finally:
        client.close()
    names = [tool.get("name") for tool in tools if isinstance(tool.get("name"), str)]
    state.emit({
        "profile": state.profile,
        "authenticated": True,
        "mcp_connected": True,
        "mcp_url": OPALSTACK_MCP_URL,
        "tool_count": len(names),
        "tools": names,
    })


@auth.command("logout")
@click.pass_obj
def logout(state):
    """Remove local credentials for this profile (does not revoke an API token)."""
    entry = state.data["profiles"].get(state.profile, {})
    if entry.get("storage") == "keyring":
        try:
            config.keyring_module().delete_password("opalagent", state.profile)
        except Exception as exc:
            raise click.ClickException("Cannot delete the keyring credential; profile was retained.") from exc
    state.data["profiles"].pop(state.profile, None)
    if state.data.get("default") == state.profile:
        state.data["default"] = next(iter(state.data["profiles"]), "default")
    config.save(state.data)
    state.emit({"profile": state.profile, "local_credentials_removed": True,
                "environment_token_still_set": bool(os.environ.get("OPALSTACK_TOKEN"))})


@cli.group()
def profiles():
    """List accounts and select the default profile."""


@profiles.command("list")
@click.pass_obj
def profiles_list(state):
    state.emit([{"name": name, "storage": value.get("storage", "file"),
                 "default": name == state.data.get("default")} for name, value in state.data["profiles"].items()],
               ["name", "storage", "default"])


@profiles.command("use")
@click.argument("name")
@click.pass_obj
def profiles_use(state, name):
    if name not in state.data["profiles"]:
        raise click.ClickException("Unknown profile. Create it with 'opalagent --profile NAME auth login'.")
    state.data["default"] = name
    config.save(state.data)
    state.emit({"default": name})


@cli.group()
def usage():
    """Read the latest web and mail resource usage."""


for kind in ("web", "mail"):
    def make_usage(kind):
        @click.command(kind)
        @click.option("--embed", multiple=True)
        @click.pass_obj
        def command(state, embed):
            state.emit(getattr(state.api.usage, f"{kind}usage_latest")(embed=list(embed)))
        return command
    usage.add_command(make_usage(kind))


@cli.command()
@click.pass_obj
def status(state):
    """Account overview with resource counts and pending provisioning."""
    result = {"profile": state.profile, "resources": []}
    for resource in ("servers", "users", "apps", "domains", "sites", "mailboxes", "mariadb-dbs", "postgres-dbs"):
        data = rows(state.manager(resource).list_all())
        result["resources"].append({"resource": resource, "total": len(data),
                                    "pending": sum(r.get("ready") is False for r in data)})
    state.emit(result)


@cli.command()
@click.option("--resource", "resources", multiple=True, type=click.Choice(list(RESOURCES)),
              help="Repeat to select resources. Defaults exclude credentials and environment variables.")
@click.pass_obj
def snapshot(state, resources):
    """Export an API inventory to stdout (metadata only; not a backup of hosted files/data)."""
    selected = resources or [r for r in RESOURCES if r not in {"tokens", "env"}]
    result = {"format": "opalstack-inventory-v1", "profile": state.profile,
              "resources": {r: state.manager(r).list_all() for r in selected}}
    display(result, "json", show_secrets=state.show_secrets)


@cli.command()
@click.argument("user")
@click.option("--identity", type=click.Path(exists=True, dir_okay=False), help="SSH identity file.")
@click.option("--port", type=click.IntRange(1, 65535), default=22)
@click.option("--print", "print_only", is_flag=True, help="Print shell-quoted command without connecting.")
@click.pass_obj
def ssh(state, user, identity, port, print_only):
    """Connect as an Opalstack shell user using your existing OpenSSH setup."""
    obj = resolve(state, "users", user, embed=("server",))
    server = obj.get("server")
    if not isinstance(server, dict):
        server = resolve(state, "servers", server)
    host = server.get("hostname", "")
    username = obj.get("name", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", host) or host.startswith("-"):
        raise click.ClickException("Invalid server hostname in API response.")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", username):
        raise click.ClickException("Invalid shell username in API response.")
    command = ["ssh", "-p", str(port)]
    if identity:
        command += ["-i", str(Path(identity).resolve())]
    command += [f"{username}@{host}"]
    if print_only:
        click.echo(shlex.join(command))
    else:
        try:
            result = subprocess.run(command, check=False)
        except FileNotFoundError as exc:
            raise click.ClickException("OpenSSH client is not installed.") from exc
        raise click.exceptions.Exit(result.returncode)


@cli.command("agent")
@click.argument("prompt", nargs=-1)
@click.option("--provider", type=click.Choice(["auto", "openai", "anthropic", "ollama"]), default="auto", show_default=True,
              help="Model provider. Auto-detects OpenAI, Anthropic, or a reachable Ollama server.")
@click.option("--mode", "work_mode", type=click.Choice(["plan", "build", "ops", "manage"]), default="plan", show_default=True,
              help="Workflow posture. PLAN/MANAGE are read-only; BUILD/OPS permit SAFE reviewed changes.")
@click.option("--tier", type=click.Choice(["auto", "lean", "normal", "heavy"]), default="auto", show_default=True,
              help="Cost/reasoning tier. Auto uses the mode default: PLAN normal, BUILD heavy, OPS normal, MANAGE normal.")
@click.option("--model", help="Exact model override. Usually prefer --tier.")
@click.option("--reasoning", type=click.Choice(["none", "low", "medium", "high", "xhigh", "max"]),
              help="Reasoning effort override. Usually prefer --tier.")
@click.option("--autopilot", is_flag=True,
              help="Skip approval for SAFE-capability mutations. Never unlocks destructive operations.")
@click.option("--dangerous", is_flag=True,
              help="Unlock destructive/arbitrary shell operations, each with typed confirmation.")
@click.option("--max-output-tokens", type=click.IntRange(256, 32768), default=4096, show_default=True)
@click.pass_obj
def agent_command(state, prompt, provider, work_mode, tier, model, reasoning, autopilot, dangerous, max_output_tokens):
    """Talk to OPAL. Starts in PLAN mode unless you choose another posture."""
    from .agent import one_shot, repl

    text = " ".join(prompt).strip()
    tier_value = None if tier == "auto" else tier
    if text:
        click.echo(one_shot(
            state, text, model, reasoning, autopilot, max_output_tokens,
            None if provider == "auto" else provider, dangerous=dangerous,
            work_mode=work_mode, tier=tier_value,
        ))
    else:
        repl(
            state, model, reasoning, autopilot, max_output_tokens,
            None if provider == "auto" else provider, dangerous=dangerous,
            work_mode=work_mode, tier=tier_value,
        )


@cli.group("vibe")
def vibe_group():
    """Manage VibeShell user-space MCP endpoints used by the agent."""


@vibe_group.command("list")
@click.pass_obj
def vibe_list(state):
    """List configured VibeShell endpoints (tokens are never printed)."""
    from .agent import load_vibes

    state.emit(
        [v.public() for v in load_vibes(state)],
        columns=["label", "user", "app", "base_dir", "exec_enabled", "url"],
    )


@vibe_group.command("add")
@click.argument("label")
@click.argument("url")
@click.option("--token", envvar="VIBESHELL_TOKEN", hide_input=True,
              help="Bearer token. Prefer the prompt or VIBESHELL_TOKEN to shell history.")
@click.option("--user", help="Optional Opalstack OS-user name for agent routing.")
@click.option("--app", help="Optional app name served by this endpoint.")
@click.option("--base-dir", default="~/apps", show_default=True)
@click.option("--enable-exec", is_flag=True,
              help="Mark this endpoint as exposing the opt-in shell_run command tool.")
@click.pass_obj
def vibe_add(state, label, url, token, user, app, base_dir, enable_exec):
    """Register an existing VibeShell endpoint."""
    from .agent import (
        VibeEndpoint, normalize_base_dir, normalize_endpoint, normalize_label, save_vibe,
    )

    if not token:
        if not sys.stdin.isatty():
            raise click.ClickException("Supply VIBESHELL_TOKEN in non-interactive use.")
        token = click.prompt("VibeShell bearer token", hide_input=True)
    try:
        base_dir = normalize_base_dir(base_dir)
    except click.ClickException as exc:
        raise click.BadParameter(exc.format_message(), param_hint="--base-dir") from exc
    endpoint = VibeEndpoint(
        label=normalize_label(label),
        url=normalize_endpoint(url),
        token=token.strip(),
        user=user,
        app=app,
        base_dir=base_dir,
        exec_enabled=enable_exec,
    )
    save_vibe(state, endpoint)
    state.emit(endpoint.public())


@vibe_group.command("remove")
@click.argument("label")
@click.option("--yes", "yes", is_flag=True)
@click.pass_obj
def vibe_remove(state, label, yes):
    """Remove a locally configured VibeShell endpoint."""
    from .agent import normalize_label, remove_vibe

    label = normalize_label(label)
    if not yes:
        if not sys.stdin.isatty():
            raise click.ClickException("Refusing non-interactive removal without --yes.")
        click.confirm(f"Remove VibeShell endpoint {label}?", abort=True)
    if not remove_vibe(state, label):
        raise click.ClickException(f"No VibeShell endpoint named {label}.")
    state.emit({"removed": label})


@vibe_group.command("adopt")
@click.argument("user")
@click.argument("app")
@click.argument("endpoint_url")
@click.option("--label", required=True, help="Local label exposed to the agent as vibe_LABEL.")
@click.pass_obj
def vibe_adopt(state, user, app, endpoint_url, label):
    """Adopt a READY installer-managed VibeShell endpoint.

    VibeShell itself must already have been provisioned by the Opalstack application
    installer. OPAL reads the installer-created credential from the matching Opalstack
    Notice Log entry, verifies MCP capabilities, and stores the secret locally without printing it.
    """
    from .agent import vibeshell_adopt

    result = vibeshell_adopt(
        state,
        {
            "user": user,
            "app": app,
            "endpoint_url": endpoint_url,
            "label": label,
        },
    )
    state.emit(result)


@cli.command()
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell):
    """Print a shell completion script. Uses Click's native completion protocol."""
    from click.shell_completion import get_completion_class
    click.echo(get_completion_class(shell)(cli, {}, "opalagent", "_OPALAGENT_COMPLETE").source())


@click.command("mark-installed")
@click.argument("selectors", nargs=-1, required=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.pass_obj
def mark_installed(state, selectors, yes, dry_run):
    """Mark apps as installed; does not execute an installer."""
    items = [resolve(state, "apps", selector) for selector in selectors]
    if dry_run:
        state.emit({"action": "mark-installed", "items": items})
        return
    confirm("mark installed", "apps", items, yes)
    state.api.apps.mark_installed([i["id"] for i in items])
    state.emit({"submitted": True, "ids": [i["id"] for i in items]})


cli.commands["apps"].add_command(mark_installed)


def main():
    try:
        cli()
    except BrokenPipeError:
        raise SystemExit(0)
    except OSError:
        click.echo("Error: Local file or system operation failed. Check paths and permissions.", err=True)
        raise SystemExit(1)

"""Atomic, owner-only profile storage. Tokens never appear in config output."""
import json
import os
from pathlib import Path
import tempfile

import click


def config_path():
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return Path(os.environ.get("OPALSTACK_CONFIG", base / "opalstack" / "config.json"))


def load():
    path = config_path()
    if not path.exists():
        return {"default": "default", "profiles": {}}
    if path.is_symlink():
        raise click.ClickException("Refusing a symlinked configuration file.")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise click.ClickException(f"Configuration permissions are too open. Run: chmod 600 {path}")
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or not isinstance(data.get("profiles"), dict):
            raise ValueError()
        if any(not isinstance(v, dict) for v in data["profiles"].values()):
            raise ValueError()
        return data
    except (ValueError, OSError) as exc:
        raise click.ClickException("Cannot read profile configuration; expected a JSON profiles object.") from exc


def save(data):
    path = config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise click.ClickException("Refusing a symlinked configuration file.")
    fd, name = tempfile.mkstemp(prefix=".config-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            os.chmod(name, 0o600)
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def keyring_module():
    try:
        import keyring
        return keyring
    except ImportError as exc:
        raise click.ClickException("Install the keyring extra: pip install 'opalagent[keyring]'") from exc


def get_token(profile, data):
    token = os.environ.get("OPALSTACK_TOKEN")
    if token:
        return token.strip()
    entry = data["profiles"].get(profile, {})
    if entry.get("storage") == "keyring":
        try:
            token = keyring_module().get_password("opalagent", profile) or keyring_module().get_password("opalstack-cli", profile)
        except click.ClickException:
            raise
        except Exception as exc:
            raise click.ClickException("Cannot unlock the system keyring.") from exc
    else:
        token = entry.get("token")
    if not isinstance(token, str) or not token.strip():
        raise click.ClickException("No Vibe MCP/API token. Run 'opalagent auth login' or set OPALSTACK_TOKEN.")
    return token.strip()

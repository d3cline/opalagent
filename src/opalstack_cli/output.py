import json
import re

import click
from rich.console import Console
from rich.table import Table

SENSITIVE = re.compile(r"password|passwd|secret|token|private|authorization|^key$|^value$", re.I)


def redact(value):
    if isinstance(value, dict):
        return {k: "[redacted]" if SENSITIVE.search(k) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def field(value, path):
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def display(value, mode="table", columns=None, show_secrets=False, stderr=False):
    value = value if show_secrets else redact(value)
    if mode == "json":
        click.echo(json.dumps(value, indent=2, ensure_ascii=False), err=stderr)
        return
    if mode == "jsonl":
        for row in value if isinstance(value, list) else [value]:
            click.echo(json.dumps(row, ensure_ascii=False))
        return
    if mode == "ids":
        for row in value if isinstance(value, list) else [value]:
            if isinstance(row, dict):
                ident = row.get("id", row.get("key"))
                if ident is not None:
                    click.echo(ident)
        return
    console = Console(highlight=False, markup=False)
    if isinstance(value, dict):
        # Preserve complex/nested data in a readable tree-shaped JSON representation.
        console.print_json(json.dumps(value, ensure_ascii=False))
        return
    if not isinstance(value, list) or not value:
        click.echo("No results." if value == [] else str(value))
        return
    if not all(isinstance(row, dict) for row in value):
        console.print_json(json.dumps(value))
        return
    fields = columns or [k for k in ("id", "name", "hostname", "type", "ready", "server", "osuser")
                         if any(k in row for row in value)]
    if not fields:
        fields = list(dict.fromkeys(k for row in value for k in row))[:6]
    table = Table(*fields, header_style="bold cyan", expand=False)
    for row in value:
        cells = []
        for key in fields:
            item = field(row, key)
            cells.append("" if item is None else json.dumps(item, ensure_ascii=False)
                         if isinstance(item, (dict, list, bool)) else str(item))
        table.add_row(*cells)
    console.print(table)

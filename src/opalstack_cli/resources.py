"""Explicit SDK capability registry: inherited methods are NOT API capabilities."""
RESOURCES = {
    "accounts": "list get update", "tokens": "list get create update delete",
    "notices": "list get create update delete", "servers": "list get", "ips": "list get",
    "domains": "list get create delete", "dns": "list get create update delete",
    "users": "list get create update delete", "env": "list get create update delete",
    "apps": "list get create update delete", "postgres-users": "list get create update delete",
    "postgres-dbs": "list get create update delete", "mariadb-users": "list get create update delete",
    "mariadb-dbs": "list get create update delete", "certs": "list get create update delete",
    "sites": "list get create update delete", "mailboxes": "list get create update delete",
    "addresses": "list get create update delete",
}
MANAGERS = {"dns": "dnsrecords", "users": "osusers", "env": "osvars",
            "postgres-users": "psqlusers", "postgres-dbs": "psqldbs",
            "mariadb-users": "mariausers", "mariadb-dbs": "mariadbs", "mailboxes": "mailusers"}
ALIASES = {v: k for k, v in MANAGERS.items()}
# Ergonomic flags for common fields; --set/--json/--file cover all other API fields.
FIELDS = {
    "domains": ["name"], "apps": ["name", "osuser", "type", "installer_url"],
    "users": ["name", "server"], "sites": ["name", "ip4"],
    "dns": ["domain", "type", "content", "ttl", "priority"],
    "mailboxes": ["name", "imap_server"], "addresses": ["source"],
    "postgres-users": ["name", "server"], "postgres-dbs": ["name", "server"],
    "mariadb-users": ["name", "server"], "mariadb-dbs": ["name", "server"],
    "certs": ["name"], "env": ["osuser", "name"], "tokens": ["name"],
}
RELATIONS = {"server": "servers", "osuser": "users", "domain": "domains",
             "imap_server": "servers", "ip4": "ips"}

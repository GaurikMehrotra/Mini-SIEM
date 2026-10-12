"""Versioned, transactional additive schema upgrades."""

import sqlite3

SCHEMA_VERSION = 3


def upgrade(db: sqlite3.Connection) -> None:
    """Upgrade development v1/v2 to v3 while preserving existing records."""
    version = db.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    if version not in (1, 2, 3):
        raise ValueError("unsupported database schema")
    additions = {
        "checkpoints": {
            "owner_path": "TEXT",
            "draining": "INTEGER DEFAULT 0",
            "source": "TEXT",
            "kind": "TEXT",
        },
        "events": {"channel": "TEXT", "original_file_name": "TEXT"},
        "alerts": {"author": "TEXT", "license": "TEXT"},
    }
    with db:
        for table, columns in additions.items():
            present = {r[1] for r in db.execute("PRAGMA table_info(" + table + ")")}
            for column, kind in columns.items():
                if column not in present:
                    # Identifiers come exclusively from this fixed migration, never logs.
                    db.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + kind)
        db.execute("INSERT OR IGNORE INTO schema_version VALUES(?)", (SCHEMA_VERSION,))

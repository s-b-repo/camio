#!/usr/bin/env python3
"""
Build a sorted, organized, deterministic SQLite catalog from the plain-text
payload base files under ``payloads/DB/base/`` and refresh ``catalog.json``.

The SQLite DB is the "pre-built" artifact the user asked for; the ``.txt``
files under ``base/`` are the transparent source of truth and the only thing
a reviewer has to trust.

Run with ``-I`` to defeat planted ``os.py`` / ``json.py`` since we read
plain-text untrusted-shape data.

Usage:
    python3 -I scripts/build-payload-db.py
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import sqlite3
import sys
import unicodedata
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
BASE_DIR = ROOT / "payloads" / "DB" / "base"
OUT_DB = ROOT / "payloads" / "DB" / "payloads.sqlite"
OUT_CATALOG = ROOT / "payloads" / "DB" / "catalog.json"

ENCODINGS = (
    "raw",
    "url",
    "url-double",
    "html",
    "html-numeric",
    "b64",
    "hex",
    "unicode-escape",
    "js-escape",
    "mixed-case",
    "null-insert",
)


def parse_header(text: str) -> tuple[str, str]:
    """Extract (category, description) from leading `# key: value` comments."""
    category = ""
    description = ""
    for line in text.splitlines():
        if not line.startswith("#"):
            break
        line = line[1:].strip()
        if line.lower().startswith("category:"):
            category = line.split(":", 1)[1].strip()
        elif line.lower().startswith("description:"):
            description = line.split(":", 1)[1].strip()
    return category, description


def load_lines(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line or line.lstrip().startswith("#"):
            continue
        out.append(line)
    return out


def encode(variant: str, value: str) -> str | None:
    """Return an encoding of ``value`` in ``variant``, or None to skip."""
    if variant == "raw":
        return value
    if variant == "url":
        return quote(value, safe="")
    if variant == "url-double":
        return quote(quote(value, safe=""), safe="")
    if variant == "html":
        return html.escape(value, quote=True)
    if variant == "html-numeric":
        return "".join(f"&#{ord(c)};" for c in value)
    if variant == "b64":
        return base64.b64encode(value.encode("utf-8", "surrogatepass")).decode("ascii")
    if variant == "hex":
        return value.encode("utf-8", "surrogatepass").hex()
    if variant == "unicode-escape":
        return "".join(
            c if (c.isascii() and c.isprintable() and c not in "\\\"'<>") else f"\\u{ord(c):04x}"
            for c in value
        )
    if variant == "js-escape":
        out = []
        for c in value:
            if c in "\\\"'<>/\n\r\t":
                out.append(f"\\x{ord(c):02x}")
            else:
                out.append(c)
        return "".join(out)
    if variant == "mixed-case":
        return "".join(
            (ch.upper() if (i % 2 == 0 and ch.isalpha()) else ch.lower() if ch.isalpha() else ch)
            for i, ch in enumerate(value)
        )
    if variant == "null-insert":
        # Insert a NUL byte representation into interesting positions — useful
        # against C string-based WAFs. Keep it readable: `\0` literal sequence.
        return "\\0" + value
    return None


def main() -> int:
    if not BASE_DIR.is_dir():
        print(f"error: {BASE_DIR} not found", file=sys.stderr)
        return 1

    # Deterministic iteration order (sorted filenames).
    files = sorted(BASE_DIR.glob("*.txt"))
    if not files:
        print(f"error: no .txt files under {BASE_DIR}", file=sys.stderr)
        return 1

    if OUT_DB.exists():
        OUT_DB.unlink()
    conn = sqlite3.connect(OUT_DB)
    conn.executescript(
        """
        PRAGMA journal_mode = DELETE;
        PRAGMA synchronous  = FULL;
        CREATE TABLE category (
            name        TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            source_file TEXT NOT NULL
        );
        CREATE TABLE payload (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            category    TEXT NOT NULL REFERENCES category(name),
            body        TEXT NOT NULL,
            encoding    TEXT NOT NULL DEFAULT 'raw',
            tags        TEXT NOT NULL DEFAULT '',
            UNIQUE(category, body, encoding)
        );
        CREATE INDEX idx_payload_category ON payload(category);
        CREATE INDEX idx_payload_encoding ON payload(encoding);
        """
    )

    catalog: dict[str, object] = {
        "version": 1,
        "categories": [],
        "total_payloads": 0,
        "encodings": list(ENCODINGS),
    }

    totals = 0

    # Categories that only make sense in raw form — encoding them adds noise.
    RAW_ONLY = {"smuggling", "headers", "jwt", "cors"}

    for path in files:
        text = path.read_text(encoding="utf-8")
        category, description = parse_header(text)
        if not category:
            category = path.stem
        if not description:
            description = f"payloads in {path.name}"
        lines = load_lines(text)
        conn.execute(
            "INSERT INTO category (name, description, source_file) VALUES (?,?,?)",
            (category, description, f"base/{path.name}"),
        )

        seen: set[tuple[str, str]] = set()
        count = 0
        raw_count = 0

        for line in lines:
            # Normalise whitespace once; preserve inner spaces.
            norm = unicodedata.normalize("NFC", line)
            for variant in ENCODINGS:
                if variant != "raw" and category in RAW_ONLY:
                    continue
                encoded = encode(variant, norm)
                if encoded is None or encoded == "":
                    continue
                key = (encoded, variant)
                if key in seen:
                    continue
                seen.add(key)
                conn.execute(
                    "INSERT OR IGNORE INTO payload (category, body, encoding) VALUES (?,?,?)",
                    (category, encoded, variant),
                )
                count += 1
                if variant == "raw":
                    raw_count += 1

        totals += count
        catalog["categories"].append(
            {
                "name": category,
                "description": description,
                "source_file": f"base/{path.name}",
                "raw_count": raw_count,
                "total_count": count,
            }
        )

    catalog["total_payloads"] = totals

    # Reset the sqlite_sequence autoincrement counter so the DB is byte-stable
    # on rebuild given the same input files.
    conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = 'payload'", (totals,))
    conn.commit()
    conn.close()

    OUT_CATALOG.write_text(
        json.dumps(catalog, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    size = OUT_DB.stat().st_size
    digest = hashlib.sha256(OUT_DB.read_bytes()).hexdigest()
    print(f"wrote {OUT_DB.relative_to(ROOT)}  ({size:,} bytes, sha256={digest[:16]}…)")
    print(f"wrote {OUT_CATALOG.relative_to(ROOT)}")
    print(f"categories: {len(catalog['categories'])}  payloads: {totals}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Camio payload database

A pre-built, **sorted, organized, transparent** payload catalog shipped with
Camio. Every payload is a short, inert probe string meant for use against
systems you are **authorized** to test — no exploits, no live-fire tooling.

| | |
|---|---|
| 📦 Location | `payloads/DB/` |
| 📄 Source of truth | `payloads/DB/base/*.txt` — hand-curated, plain text |
| 🗂 Index | `payloads/DB/catalog.json` |
| 💾 Pre-built artifact | `payloads/DB/payloads.sqlite` (generated) |
| 🧰 Builder | `scripts/build-payload-db.py` |
| 🧬 Generator | adds URL/double-URL/HTML/base64/unicode encodings |
| 🔢 Total payloads | **1200+** after expansion |

## Layout

```
payloads/DB/
├── README.md              ← this file
├── catalog.json           ← machine-readable index (category → path, count, tags)
├── payloads.sqlite        ← pre-built DB (schema below)
└── base/
    ├── xss.txt            ← reflected / stored / DOM XSS probes
    ├── sqli.txt           ← error / boolean / UNION / time-based SQLi
    ├── cmdi.txt           ← command injection (Unix + Windows + encodings)
    ├── traversal.txt      ← path traversal (raw/url/double/unicode variants)
    ├── lfi.txt            ← local-file inclusion targets (Unix + Windows)
    ├── rfi.txt            ← remote-file inclusion
    ├── ssti.txt           ← server-side template injection (Jinja/Twig/ERB/Mustache/EL)
    ├── xxe.txt            ← XML external entity
    ├── ssrf.txt           ← server-side request forgery targets + bypasses
    ├── nosqli.txt         ← NoSQL operator-based injection
    ├── open-redirect.txt  ← open-redirect bypass strings
    ├── crlf.txt           ← header / log-injection CRLF payloads
    ├── jwt.txt            ← JWT quirks (alg=none, kid traversal, HS/RS confusion)
    ├── log4shell.txt      ← JNDI / log4j lookup strings
    ├── fuzz.txt           ← metacharacter fuzz, format specifiers, buffer probes
    ├── unicode.txt        ← unicode normalization + homoglyph bypasses
    ├── smuggling.txt      ← HTTP request smuggling (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE)
    ├── headers.txt        ← header-injection + fuzz header names/values
    ├── auth-bypass.txt    ← login / 2FA / IDOR bypass patterns
    ├── path-confusion.txt ← normalisation differentials (`..;/`, `%2f`, ACL skew)
    ├── cache-deception.txt ← static-extension / path-parameter deception
    └── cors.txt           ← Origin / `null` / subdomain reflection probes
```

## Transparency

Every payload in `base/*.txt` is:

- **Readable**: one payload per line, plain UTF-8.
- **Attributable**: file-level header comment explains the category and names
  the public references (OWASP, PortSwigger academy, SecLists shapes).
- **Inert**: no RCE payloads, no shellcode, no live exploit — probe strings
  only. The matched engine still refuses to send anything out of scope.
- **Hand-curated**: not scraped from a random corpus. Lines starting with `#`
  are comments and are skipped at load time.
- **Non-destructive**: the Camio scope/policy gate still decides whether any
  of these are ever sent (`--confirm` is always required for active sends).

## Schema

`payloads.sqlite` is a single SQLite 3 database generated from the `.txt`
files. Schema is intentionally minimal so a reviewer can inspect it with
`sqlite3 payloads.sqlite '.schema'`:

```sql
CREATE TABLE category (
    name        TEXT PRIMARY KEY,   -- "xss", "sqli", "smuggling", …
    description TEXT NOT NULL,      -- one line from the file header
    source_file TEXT NOT NULL       -- path relative to payloads/DB/
);

CREATE TABLE payload (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT NOT NULL REFERENCES category(name),
    body        TEXT NOT NULL,
    encoding    TEXT NOT NULL DEFAULT 'raw',   -- raw|url|url-double|html|b64|unicode
    tags        TEXT NOT NULL DEFAULT '',      -- comma-separated labels
    UNIQUE(category, body, encoding)
);

CREATE INDEX idx_payload_category ON payload(category);
CREATE INDEX idx_payload_encoding ON payload(encoding);
```

## Rebuild

```bash
# From the workspace root:
python3 scripts/build-payload-db.py
# ⇒ writes payloads/DB/payloads.sqlite and refreshes catalog.json
```

The script is deterministic: same inputs → identical SQLite byte-for-byte
(`sqlite_sequence` is zeroed on rebuild).

## Combos and chains

Camio composes payloads into **combos** (parallel, one-from-each) and
**chains** (concatenated with a separator) for coverage probes that exercise
multiple sinks in one request. Chained combos are the backbone of the
"combo-scan" workflow:

```bash
# Build a chain: one XSS × one SQLi × one traversal, joined with `;`:
camio combo --categories xss,sqli,traversal --join ';' --limit 20
camio combo --categories smuggling,headers --mode cross-product --limit 50
```

## Passive auto-testing

When `camio proxy --auto-scan` is on, every **in-scope** captured exchange is
examined by the passive scanner and additionally by the new `input-echo`
check, which scans the response for *signatures* drawn from this DB (short
distinctive substrings like `' OR '1'='1`, `onerror=alert`, `/etc/passwd`,
`{{7*7}}`, `${jndi:`, …). Reflection of a signature already present in the
captured response is flagged — no new traffic is generated by the passive
pass.

See `docs/BUILDING.md` and `docs/PAYLOAD-DB.md` for the full operator guide.

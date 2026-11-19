<div align="center">

![Camio Payloads](https://img.shields.io/badge/CAMIO-payload%20database-1e80ff?style=for-the-badge&labelColor=020508)

![Categories](https://img.shields.io/badge/categories-25-6f42c1?style=flat-square&labelColor=020508)
![Base payloads](https://img.shields.io/badge/base%20payloads-2551-2ea043?style=flat-square&labelColor=020508)
![Total](https://img.shields.io/badge/w%2Fencodings-24611-2ea043?style=flat-square&labelColor=020508)
![Encodings](https://img.shields.io/badge/encodings-22%20context--aware-dea584?style=flat-square&labelColor=020508)
![Pre-built](https://img.shields.io/badge/pre--built-SQLite-dea584?style=flat-square&labelColor=020508)
![Chaining](https://img.shields.io/badge/payload-chaining-1e80ff?style=flat-square&labelColor=020508)

# Camio Payload Database

**Sorted, organized, transparent, pre-built** — every type of payload, combined and chained.

</div>

---

## 1. Why this exists

Camio ships a hand-curated catalog of inert payload probe strings covering
every category we actively test: **XSS, SQLi, CMDi, Traversal, LFI/RFI,
SSTI, XXE, SSRF, NoSQLi, Open-Redirect, CRLF, JWT quirks, Log4Shell, Fuzz,
Unicode-normalisation, HTTP Request Smuggling, Header-injection,
Auth-bypass, Path-confusion, Cache-deception, CORS, and general fuzz
metacharacters.**

The catalog is:

- **Pre-built** — `payloads/DB/payloads.sqlite` is committed to the repo.
- **Transparent** — the source of truth is 22 plain-text `.txt` files under
  `payloads/DB/base/` that anyone can read, diff, and audit.
- **Deterministic** — `python3 -I scripts/build-payload-db.py` regenerates
  the SQLite byte-for-byte from the `.txt` sources.
- **Organized** — one file per category, lexical ordering, `# category:`
  and `# description:` headers, blank lines and `#` comments skipped.
- **Combined + chained** — every category is cross-indexable; `camio combo`
  produces payload chains in **parallel**, **chain**, or **cross-product**
  modes for multi-sink probes.
- **Automated** — passive `input-echo` check uses DB-derived signatures to
  flag any payload-shaped echo in an in-scope capture — automatically when
  `camio proxy --auto-scan` is on.

---

## 2. Layout

```
payloads/DB/
├── README.md              ← quickstart
├── catalog.json           ← machine-readable index
├── payloads.sqlite        ← pre-built DB (1 MB, 6995 rows)
└── base/
    ├── auth-bypass.txt    ← 95   login/IDOR/role bypass
    ├── cache-deception.txt← 43   static-extension suffix tricks
    ├── cmdi.txt           ← 116  Unix + Windows command injection
    ├── cors.txt           ← 26   Origin reflection probes
    ├── crlf.txt           ← 33   header / log / response-splitting
    ├── fuzz.txt           ← 127  metacharacters + format strings
    ├── headers.txt        ← 76   header-injection & fuzz headers
    ├── jwt.txt            ← 38   alg=none / kid / jku / x5u
    ├── lfi.txt            ← 96   LFI targets + PHP wrappers
    ├── log4shell.txt      ← 25   JNDI / log4j lookups
    ├── nosqli.txt         ← 43   Mongo $ne / $regex / $where
    ├── open-redirect.txt  ← 58   userinfo / backslash / unicode
    ├── path-confusion.txt ← 79   ..;/ · %2f · ACL skew
    ├── rfi.txt            ← 28   remote-file inclusion
    ├── smuggling.txt      ← 66   CL.TE · TE.CL · TE.TE · H2.CL · H2.TE
    ├── sqli.txt           ← 138  error / boolean / UNION / time
    ├── ssrf.txt           ← 86   cloud metadata + loopback bypass
    ├── ssti.txt           ← 60   Jinja / Twig / ERB / EL / Freemarker
    ├── traversal.txt      ← 101  raw / url / double / unicode variants
    ├── unicode.txt        ← 64   normalisation + homoglyph bypasses
    ├── xss.txt            ← 140  reflected / DOM / event handlers
    └── xxe.txt            ← 30   classic / OOB / blind / XInclude

Base payloads: 1,568     After encoding expansion: 6,995
```

The builder adds four encoded variants to each raw payload (URL, double-URL,
HTML-entity, base64), except for categories flagged `RAW_ONLY` in
`scripts/build-payload-db.py` (**smuggling**, **headers**, **jwt**, **cors**)
where encoding would destroy semantics.

---

## 3. CLI

```bash
# List every pack (small built-ins + the DB categories)
camio payloads

# Show every payload in one category
camio payloads db:xss
camio payloads db:smuggling
camio payloads db:ssti

# Use a DB category as a fuzz pack (combined with `--confirm` for active)
camio fuzz 'https://target.example/item?id=§1§' \
   --attack sniper --payloads db:sqli --budget 100 --confirm

# Cluster-bomb across two DB categories
camio fuzz 'https://target.example/login?u=§a§&p=§b§' \
   --attack cluster-bomb --payloads db:auth-bypass --payloads db:sqli \
   --budget 500 --confirm

# Build a combined/chained payload set (not sent on its own)
camio combo --categories xss,sqli,traversal --mode parallel --join ';' --limit 20
camio combo --categories smuggling,headers --mode chain --join '\r\n' --limit 30
camio combo --categories xss,sqli            --mode cross-product --limit 500 \
            --out /tmp/xss-sqli.txt

# Pipe a combo straight into fuzz:
camio combo --categories xss,sqli --mode parallel --out /tmp/x.txt
camio fuzz 'https://target.example/s?q=§1§' \
   --attack sniper --payloads /tmp/x.txt --budget 200 --confirm
```

---

## 4. Combo modes

| Mode | Formula | Length | Analog |
|---|---|---|---|
| 🟦 `parallel` | pick index `i` from every set, join with `--join` | `min(len)` | Pitchfork |
| 🟪 `chain` | same as parallel but cycles short sets instead of truncating | `max(len)` | Repeat-short |
| 🟥 `cross-product` | Cartesian product, row-major | `∏ len` (cap `--limit`) | Cluster-bomb |

## 4b. Dynamic encoded-payload testing (context-aware)

Every payload is tested **raw first, then in every encoding the destination
parser accepts**. The encoding matrix lives in
[`crates/camio-automate/src/encoding.rs`](../crates/camio-automate/src/encoding.rs)
and is driven from the detected **input context**.

```bash
# List every encoding Camio ships:
camio encode --list-encodings

# List every context and the encodings it allows:
camio encode --list-contexts

# Expand a pack into every context-compatible encoding:
camio encode --payloads db:xss  --context html         --tagged
camio encode --payloads db:sqli --context url-query    --tagged
camio encode --payloads db:ssti --context json         --tagged --limit 100
camio encode --payloads db:cmdi --context header       --tagged

# Explicit encoding list (for classifier diffing):
camio encode --payloads db:xss \
   --encodings raw,html,html-numeric,html-hex,unicode-escape,b64 \
   --tagged --out /tmp/xss-encoded.txt

# Pipe into fuzz:
camio encode --payloads db:sqli --context url-query --limit 200 --out /tmp/x.txt
camio fuzz 'https://target.example/item?id=§1§' \
   --attack sniper --payloads /tmp/x.txt --budget 200 --confirm
```

### 22 encodings

| Encoding | What it does | Natural context |
|---|---|---|
| `raw` | identity (always first) | every |
| `url`, `url-double`, `url-triple` | 1×/2×/3× percent-encoding | url/form/header/cookie |
| `html`, `html-numeric`, `html-hex` | entity escape (named / `&#NN;` / `&#xNN;`) | html body/attr/xml |
| `b64`, `b64url` | standard + URL-safe base64 | json/graphql/header |
| `hex`, `hex-upper` | lowercase / uppercase hex of UTF-8 bytes | header/raw |
| `unicode-escape` | `\uXXXX` of non-printables / quotes | json/js/html |
| `js-escape` | `\xNN` of JS special chars | html-script |
| `json-escape` | RFC-8259 JSON string escape | json/graphql |
| `xml` | `& < > " '` → entities | xml |
| `sql-comment` | `/**/` inserted between SQL keywords | WAF-bypass (SQLi) |
| `mixed-case`, `upper-case`, `lower-case` | case tricks | WAF-bypass (XSS/SQLi) |
| `null-prefix`, `null-suffix` | `\0` / `%00` wrappers | path/filter bypass |
| `overlong-slash` | `/`→`%c0%af`, `.`→`%c0%ae` | path-traversal |

### Smart context detection

Given a captured request, Camio can pick the context automatically:

| Discovered input | Detected context |
|---|---|
| Query param (`?a=x`) | `url-query` |
| Form body (`application/x-www-form-urlencoded`) | `form` |
| JSON field (string) | `json` |
| JSON field (number) | `json-number` |
| Cookie | `cookie` |
| Header | `header` |

Body-level detection reads `Content-Type` (`application/json` → `json`,
`text/xml`/`+xml` → `xml`, `multipart/form-data` → `multipart`, `/graphql`
in the URL → `graphql`, …). See
[`detect_body_context`](../crates/camio-automate/src/discover.rs) +
[`DiscoveredInput::detect_context`](../crates/camio-automate/src/discover.rs).

## 4c. Payload chaining

A **chain** is an ordered sequence of HTTP steps that share named variables
(`${var}`) extracted from each other's responses. Use it when the probe
needs state — for example:

1. **Login → CSRF fetch → stored-XSS POST** (session cookie carried across
   steps, payload substituted at the final step).
2. **Trigger stored payload → open the sink to confirm reflection.**
3. **Discover a UUID → use it in the follow-up endpoint.**

The crate is [`camio-automate::chain`](../crates/camio-automate/src/chain.rs):

```rust
use camio_automate::{Chain, ChainStep, Extractor, PayloadSet, materialize_chain, ChainState};
use camio_core::HttpRequest;

let chain = Chain::new()
    // Step 1 — login; capture the session cookie.
    .push(
        ChainStep::new("login", HttpRequest::post("https://x.test/login"))
            .with_extractor(Extractor::Cookie {
                name: "sess".into(),
                var:  "session".into(),
            }),
    )
    // Step 2 — stored-XSS POST with payloads, using the captured session.
    .push(
        ChainStep::new(
            "store-xss",
            HttpRequest::post("https://x.test/comment?s=${session}"),
        )
        .with_payloads(PayloadSet::new("x", vec!["<script>alert(1)</script>".into()])),
    );

// After step 1 runs and `session` is populated into ChainState:
let state: ChainState = [("session".into(), "abc123".into())].into();
let steps = materialize_chain(&chain, &state).unwrap();
// `steps` is a flat list of ready-to-send HttpRequest with ${session}
// substituted and one request per payload at step 2.
```

**Extractors:** `Cookie{name,var}`, `Header{name,var}`,
`Between{before,after,var}`, `Regex{pattern,var}`.

**Substitution:** `${var}` reads from `ChainState`; `${payload}` substitutes
from the step's payload. Unresolved variables return
`ChainError::UnresolvedVariable` instead of sending garbled traffic.

---

## 5. Automated passive testing of in-scope input fields

When the intercepting proxy runs with `--auto-scan`, every **in-scope**
captured exchange is piped through the passive scanner. The new
**`input-echo`** check uses short distinctive substrings drawn from the
payload DB (`payloads/DB/base/*.txt`) and flags every captured response
body that contains one.

```bash
camio proxy --tls-intercept --auto-scan --db work.db \
   --scope-include 'host.eq:"target.example.com"'

# Later, review what fired:
camio findings --json | jq '.[] | select(.title | contains("payload pattern"))'
camio scan --only input-echo --db work.db
```

Severity is category-aware:

| Category | Severity | Confidence |
|---|---|---|
| sqli / ssti / cmdi / log4shell / xxe / smuggling / xss / ssrf / crlf | 🟨 Medium | Tentative |
| everything else | 🟩 Low | Tentative |

The check is **passive** — it never generates traffic. It uses the
captured response body as the source. False positives are expected
(a blog post that quotes `' OR '1'='1` will trip sqli): that's why
confidence is `Tentative` and the finding details identify both the
category and the matched signature so you can confirm in context.

---

## 6. Rebuilding

```bash
# Deterministic rebuild from base/:
python3 -I scripts/build-payload-db.py

# Verify the SQLite catalog yourself:
sqlite3 payloads/DB/payloads.sqlite '.schema'
sqlite3 payloads/DB/payloads.sqlite \
   "SELECT category, COUNT(*) FROM payload GROUP BY category ORDER BY category;"
sqlite3 payloads/DB/payloads.sqlite \
   "SELECT body FROM payload WHERE category='smuggling' AND encoding='raw' LIMIT 5;"
```

The `.txt` files are the only thing a reviewer has to trust; everything
else is reproducible from them.

---

## 7. Adding a new category or payloads

1. Create `payloads/DB/base/<name>.txt` with a header:
   ```text
   # category: <name>
   # description: one-line summary
   # references: public sources.
   ```
2. One payload per line. `#` lines and blank lines are ignored.
3. Rebuild: `python3 -I scripts/build-payload-db.py`.
4. Run `cargo test -p camio-automate -p camio-scan` to prove the loader
   picks it up and the input-echo signatures still cover it.

---

## 8. Honesty

- Every payload here is a **probe string**, not an exploit. It generates
  noise in a target's logs when sent — no privilege is gained from
  sending one.
- Camio's **scope and policy gates** (`camio scope`) still decide whether
  anything is sent. The DB only supplies candidate strings.
- Reflection of a payload-shaped substring is a passive **signal**, not a
  confirmed vulnerability. Confirm in context; use `activescan` for
  bounded, scope-gated confirmation.
- Source attribution: shapes are drawn from the public OWASP cheat
  sheets, PortSwigger academy labs, SecLists `Fuzzing/` wordlists, and
  PayloadsAllTheThings. The specific strings here are rewritten for
  Camio and do not import any third-party corpus verbatim.

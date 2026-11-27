Camio — LinkedIn post series (40)

Written in the warm, cheeky, no-nonsense Nando's-style voice (South African
flavour), for cybersecurity practitioners and people learning the craft.
Each post stands alone: hook, plain-language value, soft call-to-action, and
a short keyword line for search. No competitor names — we show what ours
does better, never who we do it against.

**Post 1 — the introduction**

Eish, we built a security testing tool and then made the one thing nobody
else fixes actually fixed.

Your proxy has a fingerprint. It waves it at every server like a passport
with your face on it. WAFs see "tool" before they see "human".

Camio is a local-first workbench where the traffic looks like the browser,
not like the tool. Free. No account. No cloud. No "trust us, we're
invisible" — we measure parity and show you the number.

If you test web apps, this is the release you tell your team about.

Keywords: web security testing, fingerprint transparency, local-first
pentest tool, open source security tooling, WAF evasion, ethical hacking
tools.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 2 — the TLS tell, explained for humans**

Imagine walking into a shop wearing a uniform that says "I AM A SECURITY
SCANNER".

That's basically your testing proxy. The way it shakes hands with the server
(the cipher order, the extensions, the order of the shifts) is different
from a real browser's handshake. Servers notice.

Camio's tool traffic goes out through an engine whose handshake is pinned to
the browser you're already using. Same fingerprint. Measured, not promised.

Keywords: TLS fingerprint, JA3, JA4, proxy detection, security testing,
penetration testing tools, bug bounty.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 3 — the one number nobody shows you**

Most security tools will tell you they're "stealthy".

Camio shows you a parity readout instead. Matched or not matched, with the
reason, in the interface. If the preset approximates the browser build, it
says so. If the dry-run engine is active (because the real one couldn't
start), the status says that too — on every send, not buried in a log.

Honesty is a feature. Especially when you're the one who has to explain your
findings to a client.

Keywords: security tool transparency, fingerprint parity, pentest reporting,
ethical hacking, cybersecurity tools.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 4 — zero config, lekker**

The old way: install tool, configure proxy, install a CA certificate, fight
with port numbers, cry a little.

The Camio way: open it, start a project, the managed browser launches,
capture is already live. Your first meaningful capture happens in seconds.

Zero-config isn't laziness. It's respecting the fact that you got work to
do.

Keywords: web app pentest setup, security workbench, bug bounty workflow,
penetration testing, zero config security tool.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 5 — free, local-first, and quiet about it**

Your targets are your business. Your API keys are your business. Your
screenshots are your business.

Camio runs on your machine, stores in your SQLite file, and phones home to
nobody. There's no "starter tier", no "pro upgrade", no seat licences, no
telemetry pixel quietly reporting what you tested.

Free as in "actually free", not free as in "free trial".

Keywords: local-first security tools, privacy-first pentesting, open source
cybersecurity, bug bounty tools, no telemetry.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 6 — Rust, and why your laptop will notice**

Java-based tools taught a generation of testers to be patient. Patience is
nice. Speed is nicer.

Camio is Rust: native window, indexed store, content-addressed bodies, and a
query language that answers in milliseconds on a million exchanges. Cold
start target is measured and gated in CI, because "it feels fast" isn't a
plan.

Your CPU fan gets to keep its day job.

Keywords: Rust security tool, fast pentest tool, memory-safe security
software, large-scale web testing, cybersecurity performance.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 7 — one query language, everywhere**

Learn one language. Use it in history, scope, intercept rules, saved
searches, and automation.

CamioQL is HTTPQL-compatible, so if you've already learned a modern query
language for traffic, you're fluent before the first coffee. One query bar,
persistent, with autocomplete and inline parse errors.

Fewer languages to hold in your head means more brain space for the actual
bugs.

Keywords: HTTPQL, query language for security testing, security workflow,
bug bounty filtering, pentest productivity.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 8 — pause a request, change it, let it go**

There's a specific joy in holding a request mid-flight, editing the header
you suspect, and watching what the server does next.

Camio's intercept queue does exactly that — pause, edit, forward, or drop.
It times out so a forgotten queue never pins your machine, and an edit is
re-checked against scope before it goes out. Because the moment you can edit
a destination is the moment your guardrails matter most.

Keywords: intercepting proxy, request editing, manual web testing, pause and
forward workflow, security testing techniques.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 9 — honest TLS interception**

Two modes, clearly labelled:

Blind relay: the browser does its own TLS, so the server sees the real
browser fingerprint, and Camio only records the host.

TLS intercept: Camio decrypts, and says plainly that this changes the
server-visible fingerprint.

Both are useful. Only one of them pretends nothing happened. Guess which one
we removed.

Keywords: TLS interception, HTTPS proxy, fingerprint transparency, manual
testing, ethical hacking workflow.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 10 — the managed browser and the matched engine work as a pair**

Organic traffic goes through the browser: the server sees the browser, full
stop.

Tool traffic (replay, fuzzing, scanning) goes through an engine pinned to
the same browser build. One fingerprint for both paths, so your testing
never introduces a signal the site can read.

That's the whole thesis. Everything else is plumbing.

Keywords: browser automation security, matched request engine, TLS parity,
security testing architecture, anti-bot testing.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 11 — scope that actually guards you**

One scope decision, shared by every surface: the app, the CLI, the web API,
the MCP server, the proxy. Private, loopback, link-local and cloud-metadata
destinations are blocked by default, and lab mode is a separate, explicit
switch — because "allow private" should never quietly mean "allow the
metadata endpoint".

When you're testing at 2am, guardrails are love.

Keywords: scope control, SSRF prevention, security testing safety,
authorized testing, penetration testing governance.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 12 — automation needs targets, not vibes**

An empty scope should not be permission to scan the internet.

In Camio, automated work requires explicit project targets. No include rule,
no discovery, no scanning, no fuzzing. It's a small rule that prevents the
kind of incident you read about on a Monday morning.

Keywords: authorized testing, pentest governance, automation safety,
cybersecurity risk, scope management.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 13 — approvals, bound to a hash**

You approved a plan. Someone edited the payload set, doubled the budget, and
pointed it at a new host. Your approval should die there.

Camio binds an approval to a hash of the plan: targets, action class, tool
version, session, limits, policy revision. Any drift invalidates it. The run
refuses, and tells you what changed.

Keywords: change control for pentesting, approval workflows, security
governance, authorized testing, audit readiness.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 14 — background jobs you can actually trust**

Long runs return a task ID immediately, stream progress, and record a
distinct outcome: success, timeout, cancelled, scope-denied, parser failure,
tool failure, storage failure.

Eight ways to end, none of them "unknown". A restart reconciles interrupted
jobs instead of pretending they never happened, and a campaign can resume
only its unexecuted remainder.

Keywords: security automation, background jobs, workflow reliability,
pentest tooling, reproducible testing.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 15 — one language for your traffic history**

A million exchanges. Query them like a database, filter them like a pro, and
never wait for the interface to catch up.

CamioQL runs over an indexed store with content-addressed bodies, so
repeated responses cost one copy and metadata queries never touch the
payload bytes.

Your history stops being a scrollbar and starts being evidence.

Keywords: traffic analysis, HTTP history, indexed security storage, bug
bounty triage, web app testing.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 16 — the scanner that runs while you browse**

Seventeen passive checks, running on in-scope traffic as you capture it:
security headers, cookie flags, secrets in URLs, CORS, JS endpoints, exposed
Swagger, GraphQL introspection, and more.

Passive means "no payloads sent". It's the safety net for the things you'd
miss at speed, and it costs the target nothing.

Keywords: passive scanning, vulnerability discovery, web security checks,
OWASP testing, learning pentesting.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 17 — active testing, opt-in and honest**

Reflected XSS, error-based SQLi, open redirects, and blind SSRF with
out-of-band callbacks. All opt-in, all gated by scope and confirmation, and
each result labelled with the confidence it deserves.

A "finding" that isn't a finding is worse than no finding. So we tell you
which is which.

Keywords: active scanning, DAST, vulnerability assessment, OAST callback,
blind SSRF detection, ethical hacking.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 18 — your own out-of-band collector, on your machine**

Blind injections need a place to call home. Camio mints its own correlation
tokens and records the callbacks: HTTP and DNS, persisted with retention, so
a callback that lands after a restart still lands in your evidence.

No third-party service. No "who else can see this interaction".

Keywords: OAST, out-of-band testing, blind SSRF, XXE detection, self-hosted
security infrastructure.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 19 — httpx, without the guesswork**

Reachability, titles, servers, technologies, TLS metadata — collected as
searchable project inventory, with the raw artifact kept for provenance.

And if the httpx on your PATH isn't ProjectDiscovery's Go tool, Camio says
so instead of quietly producing zero results and letting you think the host
was down.

Keywords: HTTP probing, attack surface inventory, technology detection,
reconnaissance, bug bounty workflow.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 20 — Nuclei results that keep their receipts**

Every finding carries its template ID, severity, the exact matched location,
and the raw JSONL artifact — so you can re-parse without re-running, and
retest without launching unrelated templates.

Tool output becomes project data, not terminal scrollback.

Keywords: Nuclei, vulnerability scanning integration, template scanning,
security evidence, reproducible findings.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 21 — imports that respect your history**

Bring an existing session export or a HAR file, and Camio preserves header
order, casing, duplicates and exact body bytes. Imported headers that carry
control characters are refused with a warning, because a stored request
you're going to replay is a request you should trust.

Migration is a feature. Trusting your inputs is a decision.

Keywords: HAR import, session export migration, security tool migration,
evidence preservation, pentest workflow.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 22 — findings triage that survives contact with reality**

Statuses (open, confirmed, false positive, fixed, ignored), notes, labels,
cross-run correlation, and report exports that include scope, versions, and
what did and didn't run.

Because "45 findings" means nothing until someone can act on them.

Keywords: vulnerability management, findings triage, security reporting,
penetration test report, remediation tracking.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 23 — the utilities you actually use**

Convert (every encoding, reusable in workflows), Comparer, unified diff
between two exchanges, JWT decoding without pretending to verify, Sequencer
for token randomness with an honest statistical caveat.

Small tools, done properly, reachable from the CLI, the web UI, MCP, and
workflows.

Keywords: security utilities, encoding tools, JWT analysis, randomness
testing, pentest toolkit.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 24 — campaigns with a budget and a receipt**

Intruder-class fuzzing over marked insertion points, with a projected count
before anything is sent, a ceiling that can't be exceeded, URL-position
payloads encoded so the request you projected is the request that goes out,
and results classified against a baseline instead of "it returned 200".

Plus: a 1-character payload no longer marks every response as a reflection.

Keywords: fuzzing, intrusion testing, payload encoding, web app security,
automated pentesting.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 25 — the crawl that stays where you told it**

Same-origin means same scheme, same host, same port. A page seeded on https
doesn't silently enqueue the http downgrade or the service on another port.

Small detail. Large "thank goodness someone caught that".

Keywords: web crawling, attack surface mapping, site map, recon automation,
security testing scope.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 26 — WebSocket frames you can read and edit**

We decode RFC 6455 frames in both directions, let you rewrite text payloads
in flight, and relay anything that isn't a frame byte-for-byte.

Match & Replace now applies to the handshake too, and a TLS upgrade is
refused honestly rather than sent in the clear.

Keywords: WebSocket security testing, frame inspection, real-time app
testing, manual pentesting, proxy features.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 27 — chain your proxy, keep your head**

Upstream chaining works for the raw relay paths too now: blind tunnels and
ws:// dials go through your HTTP or SOCKS5 upstream, not just
engine-forwarded traffic.

And an unknown scheme gets refused, because silently going direct is how
leaks happen.

Keywords: proxy chaining, SOCKS5, penetration testing setup, network
security, tool interoperability.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 28 — the CA you can rotate**

You imported our CA into a browser. Now it's time for a new one.
`--rotate-ca` mints a fresh key and certificate and tells you to re-import;
`--remove-ca` stops us minting leaves as that identity at all.

The private key was created 0600 from the very first byte, by the way. No
world-readable window, no "we'll fix it with a chmod later".

Keywords: TLS certificate authority, MITM proxy security, certificate
rotation, ethical interception, security hygiene.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 29 — four front doors, one brain**

Native app, CLI, local web API, MCP server. Same scope decisions, same
policy, same task IDs, same outcomes.

Start a run from the CLI at midnight, check its progress in the app, cancel
it from your AI assistant. The work doesn't care which door you used.

Keywords: security tool parity, MCP server, CLI pentest tools, API-driven
security, automation integration.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 30 — an AI assistant that can't approve itself**

Optional, bring-your-own-key, and gated: the AI can explain evidence,
suggest queries, and draft plans, but it cannot grant permissions or
authorize execution. Imported text is treated as untrusted data, never
instructions.

Useful copilot, zero authority.

Keywords: AI in cybersecurity, MCP, AI-assisted pentesting, prompt injection
defense, secure automation.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 31 — the hardening story, told plainly**

We ran six parallel reviews across every crate and fixed 60+ findings:
request corruption in the proxy, an SSRF bypass in the intercept queue,
panics on multi-byte characters, unbounded reads that could OOM a process,
predictable correlation tokens, credential values written into findings.

Then we wrote regression tests for all of them.

That's the part of the iceberg you don't see. The other part is a tool that
works.

Keywords: secure development, security code review, vulnerability
remediation, Rust security, software supply chain.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 32 — packaging that a reviewer can check**

Signed release binaries for Linux and macOS (x86_64 and arm64), an SBOM
generated from cargo metadata, cargo-deny on
advisories/bans/licenses/sources, and CI gates that break the build on a
clippy warning.

When your customers' security team asks "what's in this box?", the answer is
a file, not a shrug.

Keywords: SBOM, software supply chain security, release engineering, secure
packaging, open source governance.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 33 — for the learners: your first 15 minutes**

Install, open, start a project, launch the browser, capture traffic, filter
it with a query, replay one request, label it, export a report.

That's the whole loop. No CA import fight, no proxy config, no "watch this
40-minute setup video first".

Learning security should be about security, not about tooling.

Keywords: learn pentesting, beginner ethical hacking, web security tutorial,
getting started with bug bounty, cybersecurity learning.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 34 — for the bug bounty hunters**

Scope rules, deduplicated inventory, findings with evidence you can paste
into a report, and a replay flow that doesn't corrupt the request you meant
to send.

When a triager asks "show me", you have bytes, not vibes.

Keywords: bug bounty, vulnerability disclosure, recon workflow, evidence
collection, hunter tools.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 35 — for the consultants**

Per-project workspaces, backups, findings with triage status, reports that
carry their own scope and version metadata, durable task records with
distinct outcomes.

Your client's auditor will love you. Your future self, on the next
engagement, will love you more.

Keywords: penetration test delivery, consulting workflow, audit readiness,
security reporting, client deliverables.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 36 — progressive disclosure, properly done**

Simple by default: open, capture, look. Power on demand: raw bytes, hex
views, CamioQL, workflow nodes, fingerprint internals, extension hooks.

An interface that hides complexity until you ask for it beats one that
apologises for it.

Keywords: security UX, tool design, pentest interface, usability in security
tools, developer experience.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 37 — keyboard-first, because mice are slow**

Command palette, documented shortcuts, and a results table with real
navigation: multi-select, keyboard movement, copy, export.

Every core action in a couple of keystrokes. Your hands stay where your
brain is.

Keywords: keyboard-driven tools, productivity for pentesters, security
workflow efficiency, accessible security tooling.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 38 — we never say "invisible"**

No tool can promise that. What Camio promises is narrower and actually true:
we don't add a tell. We don't stamp a proxy's TLS onto browser-shaped
traffic, we preserve the exact header order and casing, and we measure
parity against the browser build instead of asserting it.

Under-promise, measure, deliver.

Keywords: fingerprint transparency, honest security marketing, anti-bot
testing, WAF detection evasion, measured security.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 39 — open source with a spine**

MPL-2.0, no paid tier, no feature gates, no "enterprise edition" that
removes the ceiling on exchanges you can store. Every gate we hold ourselves
to is in CI, public, and reproducible.

If a feature isn't free, it isn't done.

Keywords: open source security tools, MPL license, free pentesting software,
community-driven security, sustainable open source.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

**Post 40 — the invitation**

If you test web applications, or you're learning how, come and look. Run it
against your own lab, break it, tell us what's ugly.

We built this because the tool that respected your target's fingerprint,
your machine's resources, and your intelligence didn't exist yet.

It does now. Lekker, hey.

Keywords: open source pentest tool, local-first security workbench, try
Camio, cybersecurity community, web application security testing.

#cybersec   https://github.com/s-b-repo/camio/releases   cybersec.org.za

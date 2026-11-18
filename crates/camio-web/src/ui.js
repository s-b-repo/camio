"use strict";

const S = Object.create(null);
const $ = id => document.getElementById(id);
const v = id => $(id)?.value ?? "";
const ck = id => Boolean($(id)?.checked);
const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
})[char]);
const titleCase = value => String(value).replace(/^\w/, letter => letter.toUpperCase());
const bytes = value => value === null || value === undefined ? "—" : Number(value).toLocaleString() + " B";
const out = (id, html) => { if ($(id)) $(id).innerHTML = html; };
const err = (id, error) => out(id, '<p class="err" role="alert">' + esc(error.message || error) + "</p>");
const output = (id, value) => { if ($(id)) $(id).textContent = value; };
const announce = message => output("announcer", message);
const button = (label, attrs, kind = "ghost") => '<button type="button" class="' + kind + '" ' + attrs + ">" + esc(label) + "</button>";
const badge = state => '<span class="badge state-' + esc(state) + '">' + esc(titleCase(state)) + "</span>";
const sevClass = value => "sev-" + (["critical", "high", "medium", "low", "info"].includes(value) ? value : "info");
const loading = '<p class="statusline" role="status">Loading…</p>';
const statuses = ["open", "confirmed", "resolved", "dismissed"];
const stateOptions = (selected, all = false) => (all ? '<option value="">All statuses</option>' : "")
  + statuses.map(state => '<option value="' + state + '"' + (selected === state ? " selected" : "") + ">" + titleCase(state) + "</option>").join("");

const NAV = [
  ["Workspace", [["status", "Overview", "▦"], ["workflows", "Review workflows", "⊚"], ["tasks", "Review tasks", "◷"], ["library", "Library", "◇"]]],
  ["Traffic", [["history", "History", "≡"], ["query", "CamioQL", "⌕"], ["sitemap", "Site map", "┬"], ["inventory", "Asset inventory", "⊞"], ["replay", "Replay", "↻"], ["discover", "Discover inputs", "⊞"]]],
  ["Review", [["scan", "Passive review", "◎"], ["findings", "Findings", "△"], ["import", "Import traffic", "↓"], ["integrations", "Integration evidence", "⇥"], ["fuzz", "Automate / Fuzz", "⋮"]]],
  ["Utilities", [["convert", "Convert", "⇄"], ["comparer", "Comparer", "≠"], ["jwt", "JWT decode", "{}"], ["sequencer", "Sequencer", "∿"], ["analyze", "Analyze JS", "⌁"], ["scope", "Scope check", "⊙"], ["payloads", "Payloads", "▤"]]],
  ["Settings", [["fingerprint", "Transport", "◉"], ["settings", "Workspace settings", "⚙"]]]
];
const TOOLS = NAV.flatMap(([, items]) => items);
const LABELS = Object.fromEntries(TOOLS.map(([id, label]) => [id, label]));

let current = null;
let sessionKey = "";
let meta = null;
let workspace = null;
let inspector = null;

function connection(state, warning = "") {
  $("connection").dataset.state = state;
  $("connection-label").textContent = ({ connecting: "Connecting", connected: "Local session", offline: "Offline" })[state];
  $("session-message").hidden = !warning;
  $("session-message").textContent = warning;
}
async function api(path, payload) {
  let response;
  try {
    response = await fetch("/api/" + path.replace(/^\/api\//, ""), {
      method: payload === undefined ? "GET" : "POST",
      headers: { "Authorization": "Bearer " + sessionKey, "Content-Type": "application/json" },
      body: payload === undefined ? undefined : JSON.stringify(payload),
      cache: "no-store"
    });
  } catch (error) {
    connection("offline", "The local Camio process is unreachable.");
    throw error;
  }
  const result = await response.json();
  if (response.status === 401) connection("offline", "Open the full session link printed by Camio to connect to this workspace.");
  else connection("connected");
  if (!response.ok || result.error) throw new Error(result.error || ("HTTP " + response.status));
  return result;
}
function download(filename, text) {
  const link = document.createElement("a");
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 2000);
}
async function selectedText(fileInput, textInput) {
  const file = $(fileInput).files[0];
  if (file?.size > 4 * 1024 * 1024) throw new Error("Select a file of up to 4 MiB.");
  const text = file ? new TextDecoder("utf-8", {fatal:true, ignoreBOM:true}).decode(await file.arrayBuffer()) : v(textInput);
  if (!text.trim()) throw new Error("Select a file or paste its contents.");
  return text;
}

function exchangeTable(rows, sort = null) {
  if (!rows.length) return '<div class="empty"><p>No exchanges on this page.</p></div>';
  const columns = [["id", "ID"], ["method", "Method"], ["status", "Status"], ["source", "Source"], ["url", "URL"], ["resp_len", "Response"]];
  const heading = columns.map(([key, label]) => {
    if (!sort) return '<th scope="col">' + label + "</th>";
    const direction = sort.key === key ? (sort.asc ? "ascending" : "descending") : "none";
    return '<th scope="col" aria-sort="' + direction + '">' + button(label + (direction === "none" ? "" : sort.asc ? " ↑" : " ↓"),
      'data-sort="' + key + '"', "") + "</th>";
  }).join("");
  return '<div class="tablewrap"><table><thead><tr>' + heading + "</tr></thead><tbody>"
    + rows.map(row => "<tr><td>" + button("#" + row.id, 'data-exchange="' + esc(row.id) + '"', "text-button mono")
      + '</td><td><span class="method">' + esc(row.method) + '</span></td><td><span class="code" data-status="' + esc(row.status) + '">'
      + esc(row.status ?? "—") + '</span></td><td>' + esc(row.source) + '</td><td class="mono"><span class="table-url">'
      + esc(row.url) + "</span></td><td>" + esc(bytes(row.resp_len)) + "</td></tr>").join("") + "</tbody></table></div>";
}
function evidenceButtons(ids) {
  if (!ids?.length) return '<p class="hint">No linked exchanges.</p>';
  return '<div class="evidence-list">' + ids.map(id => button("Exchange #" + id, 'data-exchange="' + esc(id) + '"', "ghost small")).join("") + "</div>";
}
function findingTable(rows) {
  if (!rows.length) return '<div class="empty"><p>No findings on this page.</p></div>';
  return '<div class="tablewrap"><table><thead><tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Status</th></tr></thead><tbody>'
    + rows.map(row => '<tr><td class="' + sevClass(row.severity) + '">' + esc(titleCase(row.severity))
      + "</td><td>" + esc(titleCase(row.confidence)) + "</td><td><details><summary>" + esc(row.title) + "</summary>"
      + '<p>' + esc(row.detail) + "</p>" + evidenceButtons(row.evidence)
      + (row.state ? button("Triage finding #" + row.id, 'data-finding="' + esc(row.id) + '"', "ghost small") : "")
      + "</details></td><td>" + (row.state ? badge(row.state) : row.id ? "Saved" : "Preview")
      + "</td></tr>").join("") + "</tbody></table></div>";
}
S.sitemap = {html:`<h2>Site map</h2><p class="hint">Origin → path tree built from history.</p>
  <label for="sm_q">Filter (CamioQL, optional)</label><input id="sm_q" placeholder="(all)">
  <button class="go" data-action="sitemap.run">Build</button><pre class="out" id="o_sitemap"></pre>`,
  async run(){ try{const j=await api("/api/sitemap",{query:v("sm_q")}); out("o_sitemap",esc(j.tree||"(empty)")+"\n— "+j.origin_count+" origin(s), "+j.url_count+" URL(s)"); }catch(e){err("o_sitemap",e);} }};


S.replay = {html:`<h2>Replay / Send</h2><p class="hint">Send through the fingerprint-matched engine. Policy-gated: in-scope + confirm to send.</p>
  <div class="row"><div class="narrow"><label for="r_m">Method</label><input id="r_m" value="GET"></div>
  <div class="wide"><label for="r_url">URL</label><input id="r_url" placeholder="https://example.org/"></div></div>
  <label for="r_h">Headers (one per line, Name: Value)</label><textarea id="r_h"></textarea>
  <label for="r_b">Body</label><textarea id="r_b"></textarea>
  <label class="chk"><input type="checkbox" id="r_c"> confirm (actually send)</label>
  <button class="go" data-action="replay.run">Send</button><div class="out" id="o_replay"></div>`,
  async run(){ try{const j=await api("/api/send",{url:v("r_url"),method:v("r_m"),headers:v("r_h"),body:v("r_b"),confirm:ck("r_c")});
    if(j.status==="confirmation_required"){ out("o_replay",'<div class="err">'+esc(j.reason)+'</div><pre class="out">'+esc(JSON.stringify(j.preview,null,2))+'</pre>'); return; }
    let h='<p class="hint">'+esc(j.method)+' '+esc(j.url)+' → '+esc(j.status)+' ('+esc(j.resp_len)+' bytes, '+esc(j.roundtrip_ms)+' ms, stored #'+esc(j.stored_id)+')</p>';
    if(j.response_headers&&j.response_headers.length){ h+='<pre class="out">'+j.response_headers.map(x=>esc(x[0]+": "+x[1])).join("\n")+'</pre>'; }
    h+='<pre class="out">'+esc(j.response_body||"")+'</pre>'; out("o_replay",h);
  }catch(e){err("o_replay",e);} }};


S.discover = {html:`<h2>Discover inputs</h2><p class="hint">Enumerate injectable inputs of a request.</p>
  <div class="row"><div class="narrow"><label for="d_m">Method</label><input id="d_m" value="GET"></div>
  <div class="wide"><label for="d_url">URL</label><input id="d_url" placeholder="https://x.test/s?q=1&id=2"></div></div>
  <label for="d_h">Headers</label><textarea id="d_h" placeholder="Cookie: sid=abc"></textarea>
  <label for="d_b">Body</label><textarea id="d_b"></textarea>
  <button class="go" data-action="discover.run">Discover</button><div class="out" id="o_discover"></div>`,
  async run(){ try{const j=await api("/api/discover",{url:v("d_url"),method:v("d_m"),headers:v("d_h"),body:v("d_b")});
    let h='<p class="hint">'+j.count+' input(s)</p><div class="tablewrap"><table><tr><th>Kind</th><th>Name</th><th>Value</th></tr>';
    for(const i of j.inputs){ h+='<tr><td>'+esc(i.kind)+'</td><td>'+esc(i.name)+'</td><td class="mono">'+esc(i.value)+'</td></tr>'; }
    out("o_discover",h+'</table></div>'); }catch(e){err("o_discover",e);} }};


S.fuzz = {html:`<h2>Automate / Fuzz</h2><p class="hint">Mark insertion points with §…§ (e.g. <code>id=§1§</code>). <b>Plan</b> shows the projected count; <b>Run</b> sends (in-scope + confirm).</p>
  <div class="row"><div class="narrow"><label for="f_m">Method</label><input id="f_m" value="GET"></div>
  <div class="wide"><label for="f_url">URL</label><input id="f_url" placeholder="https://example.org/item?id=§1§"></div></div>
  <label for="f_h">Headers</label><textarea id="f_h"></textarea><label for="f_b">Body</label><textarea id="f_b"></textarea>
  <div class="row">
    <div><label for="f_a">Attack</label><select id="f_a"><option>sniper</option><option>battering_ram</option><option>pitchfork</option><option>cluster_bomb</option></select></div>
    <div><label for="f_p">Payload packs (comma)</label><input id="f_p" placeholder="sqli,xss"></div>
    <div><label for="f_budget">Budget</label><input id="f_budget" type="number" value="200"></div>
  </div>
  <label class="chk"><input type="checkbox" id="f_c"> confirm (run the active test)</label>
  <div class="inline"><button class="go" data-action="fuzz.plan">Plan</button>
  <button class="go ghost" data-action="fuzz.run">Run</button></div><div class="out" id="o_fuzz"></div>`,
  packs(){ return v("f_p").split(",").map(s=>s.trim()).filter(Boolean); },
  body(){ return {url:v("f_url"),method:v("f_m"),headers:v("f_h"),body:v("f_b"),attack:v("f_a"),payloads:this.packs(),budget:+v("f_budget")}; },
  async plan(){ try{const j=await api("/api/fuzz_plan",this.body());
    out("o_fuzz",'<pre class="out">'+esc(JSON.stringify(j,null,2))+'</pre>'); }catch(e){err("o_fuzz",e);} },
  async run(){ try{const b=this.body(); b.confirm=ck("f_c"); const j=await api("/api/fuzz_run",b);
    if(j.status==="confirmation_required"){ out("o_fuzz",'<div class="err">'+esc(j.reason)+'</div><pre class="out">'+esc(JSON.stringify(j.plan,null,2))+'</pre>'); return; }
    let h='<p class="hint">sent '+j.sent+' request(s)</p><div class="tablewrap"><table><tr><th>Code</th><th>Len</th><th>Flags</th><th>Payload</th></tr>';
    for(const r of j.results){ h+='<tr><td>'+esc(r.status??"-")+'</td><td>'+esc(r.body_len??"-")+'</td><td>'+(r.flags||[]).map(f=>'<span class="pill">'+esc(f)+'</span>').join("")+'</td><td class="mono">'+esc((r.payloads||[]).join(" | "))+'</td></tr>'; }
    out("o_fuzz",h+'</table></div>'); }catch(e){err("o_fuzz",e);} }};


S.convert = {html:`<h2>Convert</h2><p class="hint">Pipeline runs left→right. e.g. <code>base64,gzip</code> or <code>base64-decode</code>. <span id="tx_hint"></span></p>
  <label for="cv_in">Input</label><textarea id="cv_in"></textarea>
  <label for="cv_steps">Steps (comma-separated)</label><input id="cv_steps" placeholder="base64">
  <button class="go" data-action="convert.run">Apply</button><div class="out" id="o_convert"></div>`,
  async run(){ try{const j=await api("/api/convert",{input:v("cv_in"),steps:v("cv_steps")});
    out("o_convert",'<p class="hint">'+j.output_len+' bytes · '+esc(j.steps.join(" → "))+'</p><pre class="out">'+esc(j.output_text)+'</pre><label>hex</label><pre class="out">'+esc(j.output_hex)+'</pre>'); }catch(e){err("o_convert",e);} }};


S.jwt = {html:`<h2>JWT decode</h2><p class="hint">Decodes header + payload. The signature is NOT verified.</p>
  <label for="jw_t">Token</label><textarea id="jw_t"></textarea>
  <button class="go" data-action="jwt.run">Decode</button><div class="out" id="o_jwt"></div>`,
  async run(){ try{const j=await api("/api/jwt",{token:v("jw_t").trim()});
    out("o_jwt",'<label>header</label><pre class="out">'+esc(j.header)+'</pre><label>payload</label><pre class="out">'+esc(j.payload)+'</pre><p class="hint">signature not verified — claims are untrusted.</p>'); }catch(e){err("o_jwt",e);} }};


S.sequencer = {html:`<h2>Sequencer</h2><p class="hint">Entropy estimate for session tokens (one per line). Statistical estimate, not a proof.</p>
  <label for="sq_t">Samples</label><textarea id="sq_t" class="tall"></textarea>
  <button class="go" data-action="sequencer.run">Analyze</button><pre class="out" id="o_sequencer"></pre>`,
  async run(){ try{const j=await api("/api/sequencer",{text:v("sq_t")}); out("o_sequencer",esc(JSON.stringify(j,null,2))); }catch(e){err("o_sequencer",e);} }};


S.scope = {html:`<h2>Scope check</h2><p class="hint">The one shared scope path (SSRF guard runs first).</p>
  <label for="sp_url">URL</label><input id="sp_url" placeholder="http://169.254.169.254/">
  <button class="go" data-action="scope.run">Check</button><div class="out" id="o_scope"></div>`,
  async run(){ try{const j=await api("/api/scope",{url:v("sp_url")});
    const cls = j.decision==="in_scope"?"ok":"bad";
    out("o_scope",'<p class="hint">'+esc(j.url)+' → <span class="badge '+cls+'">'+esc(j.decision)+'</span></p>'); }catch(e){err("o_scope",e);} }};


S.payloads = {html:`<h2>Payloads</h2><p class="hint">Built-in packs — for AUTHORIZED testing only.</p>
  <button class="go" data-action="payloads.run">Load</button><div class="out" id="o_payloads"></div>`,
  async run(){ try{const j=await api("/api/payloads",{});
    let h='';for(const p of j.packs){ h+='<p><b>'+esc(p.name)+'</b> <span class="hint">('+p.size+')</span><br>'+(p.sample||[]).map(s=>'<span class="pill mono">'+esc(s)+'</span>').join(" ")+'</p>'; }
    out("o_payloads",h); }catch(e){err("o_payloads",e);} }};


S.status = {
  html: [
    '<div class="hero"><div class="hero-grid" aria-hidden="true"></div><div>',
    '<div class="eyebrow"><span class="pulse" aria-hidden="true"></span>Workspace overview</div>',
    '<h1 id="overview-name" tabindex="-1">Local workspace</h1><p class="hint" id="overview-hint">Review traffic and evidence stored in this project.</p>',
    '<div class="hero-actions"><button class="go" data-go="import">Import traffic</button><button class="ghost" data-go="history">Browse history <span class="arrow" aria-hidden="true">→</span></button></div></div>',
    '<div class="instrument"><div class="instrument-title">Request transport</div><dl id="overview-transport"><dt>Status</dt><dd>Connecting…</dd></dl></div></div>',
    '<div class="metrics" id="metrics" aria-label="Workspace totals"></div>',
    '<div class="dashboard-lower"><div class="panel"><div class="panel-head"><h2>Recent traffic</h2><button class="ghost small" data-go="history">View history</button></div><div id="overview-traffic"></div></div>',
    '<div class="panel"><div class="panel-head"><h2>Review tasks</h2><button class="ghost small" data-go="tasks">View tasks</button></div><div class="panel-body task-list" id="overview-tasks"></div></div></div>'
  ].join(""),
  async enter() {
    if (meta) this.transport();
    try {
      const data = await api("workspace", {});
      setWorkspace(data.workspace);
      output("overview-name", workspace.project.name);
      output("overview-hint", workspace.exchanges
        ? "Review captured exchanges and track the findings they support."
        : "Import a capture to start reviewing traffic and evidence.");
      out("metrics", [
        ["history", "Exchanges", workspace.exchanges, "≡"], ["findings", "Open findings", workspace.open_findings, "△"],
        ["integrations", "Imported artifacts", workspace.artifacts, "⇥"], ["library", "Saved exchanges", workspace.saved_exchanges, "◇"]
      ].map(([view, label, count, icon]) => '<button class="metric" data-go="' + view + '"><span class="metric-icon" aria-hidden="true">'
        + icon + '</span><span class="arrow" aria-hidden="true">↗</span><strong>' + Number(count).toLocaleString() + "</strong><small>" + label + "</small></button>").join(""));
      out("overview-traffic", data.exchanges.length ? exchangeTable(data.exchanges) : '<div class="empty"><p>No traffic has been recorded here.</p><button class="ghost small" data-go="import">Import a HAR or Burp archive</button></div>');
      out("overview-tasks", data.tasks.length ? taskLinks(data.tasks) : '<div class="empty"><p>Review runs will appear here.</p><button class="ghost small" data-go="scan">Start a passive review</button></div>');
    } catch (error) {
      if (sessionKey) err("overview-traffic", error);
    }
  },
  transport() {
    out("overview-transport", "<dt>Engine</dt><dd>" + esc(meta.engine) + "</dd><dt>Profile</dt><dd>" + esc(meta.profile)
      + "</dd><dt>Target</dt><dd>" + esc(meta.fingerprint_target) + "</dd><dt>Parity</dt><dd>Unverified</dd>");
  }
};
function setWorkspace(value) {
  workspace = value;
  output("workspace-name", workspace.project.name);
  if ($("workspace-input") && !v("workspace-input")) $("workspace-input").value = workspace.project.name;
}

function historySurface(search) {
  const id = search ? "query" : "history";
  const target = "o_" + id;
  return {
    html: '<h1 tabindex="-1">' + (search ? "CamioQL" : "History") + '</h1><p class="hint">'
      + (search ? "Filter stored exchanges by method, URL, status, headers, or body text." : "Inspect stored exchanges and save evidence to the library.")
      + '</p><div class="card"><div class="row"><div class="grow"><label for="' + id + '_q">CamioQL filter</label><input class="mono" id="' + id
      + '_q" maxlength="1024" list="query-examples" placeholder="resp.code.gte:400"></div><div class="narrow"><label for="' + id
      + '_limit">Page size</label><select id="' + id + '_limit"><option>25</option><option selected>50</option><option>100</option><option>200</option></select></div></div>'
      + '<div class="toolbar"><button class="go" data-action="' + id + '.reset">Apply filter</button><button class="ghost" data-action="' + id + '.clear">Clear</button>'
      + '<label class="sr-only" for="' + id + '_saved">Saved queries</label><select class="toolbar-select" id="' + id + '_saved"><option value="">Saved queries</option></select>'
      + '<button class="ghost" data-action="' + id + '.useSaved">Load saved query</button></div><details><summary>Save current query</summary>'
      + '<label for="' + id + '_name">Query name</label><input id="' + id + '_name" maxlength="100"><button class="go ghost" data-action="' + id + '.save">Save query</button>'
      + '</details></div><div class="out" id="' + target + '"></div>',
    cursors: [null],
    sort: { key: "id", asc: false },
    filter: "",
    limit: 50,
    result: null,
    requestId: 0,
    async enter() {
      await Promise.all([this.result ? Promise.resolve() : this.reset(), this.loadSaved()]);
    },
    async reset() {
      this.filter = v(id + "_q").trim();
      this.limit = Number(v(id + "_limit"));
      this.cursors = [null];
      await this.load();
    },
    async clear() {
      $(id + "_q").value = "";
      await this.reset();
    },
    async next() {
      this.cursors.push(this.result.next_before);
      await this.load();
    },
    async previous() {
      this.cursors.pop();
      await this.load();
    },
    async load() {
      const requestId = ++this.requestId;
      out(target, loading);
      try {
        const result = await api("query", { query: this.filter, before: this.cursors.at(-1), limit: this.limit });
        if (requestId !== this.requestId) return;
        this.result = result;
        this.render();
        announce(this.result.count + " exchanges on page " + this.cursors.length);
      } catch (error) { if (requestId === this.requestId) err(target, error); }
    },
    render() {
      const rows = [...this.result.exchanges];
      const {key, asc} = this.sort;
      rows.sort((left, right) => {
        const a = left[key] ?? "", b = right[key] ?? "";
        const cmp = typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b));
        return asc ? cmp : -cmp;
      });
      out(target, '<div class="toolbar"><span class="statusline">' + rows.length + " exchanges · Page " + this.cursors.length
        + (this.result.skipped_large ? " · " + this.result.skipped_large + " oversized exchanges skipped in body search" : "")
        + '</span><span class="spacer"></span>'
        + (this.cursors.length > 1 ? button("Previous", 'data-action="' + id + '.previous"') : "")
        + (this.result.next_before ? button("Next", 'data-action="' + id + '.next"') : "")
        + "</div>" + exchangeTable(rows, this.sort));
    },
    async loadSaved() {
      try {
        const result = await api("queries", {});
        const select = $(id + "_saved");
        select.replaceChildren(new Option("Saved queries", ""));
        for (const query of result.queries) select.add(new Option(query.name, query.expression));
      } catch (error) { if (!this.result && sessionKey) err(target, error); }
    },
    async useSaved() {
      if (v(id + "_saved")) {
        $(id + "_q").value = v(id + "_saved");
        await this.reset();
      }
    },
    async save() {
      await api("queries/save", { name: v(id + "_name"), expression: v(id + "_q") });
      await this.loadSaved();
      announce("Saved query " + v(id + "_name"));
      $(id + "_name").value = "";
    }
  };
}
S.history = historySurface(false);
S.query = historySurface(true);

S.scan = {
  html: '<h1 tabindex="-1">Passive review</h1><p class="hint">Run built-in checks against stored exchanges. Results link back to their evidence.</p>'
    + '<div class="card"><div class="row"><div class="grow"><label for="sc_q">CamioQL filter</label><input id="sc_q" class="mono" list="query-examples" maxlength="1024" placeholder="Every exchange in the review window"></div>'
    + '<div><label for="sc_limit">Recent exchanges to examine</label><input id="sc_limit" type="number" min="1" max="1000" value="200"></div></div>'
    + '<label class="chk"><input type="checkbox" id="sc_save" checked> Add findings to triage</label><div class="toolbar"><button class="go" data-action="scan.run">Start review</button>'
    + '<button class="ghost" data-go="tasks">View tasks</button></div></div><div id="o_scan"></div>',
  async run() {
    try {
      const result = await api("review/start", { query: v("sc_q"), limit: Number(v("sc_limit")), save: ck("sc_save") });
      S.tasks.selected = result.id;
      S.tasks.offset = 0;
      show("tasks");
      announce("Started review " + result.id);
    } catch (error) { err("o_scan", error); }
  }
};
function taskLinks(tasks) {
  return tasks.map(job => '<button type="button" class="task-link" data-task="' + esc(job.id) + '"><span><strong>' + esc(job.workflow?.name || "Passive review") + ' #' + esc(job.id)
    + '</strong><small>' + esc(job.scanned) + " scanned · " + esc(job.findings) + "</small></span>" + badge(job.state) + "</button>").join("");
}
function archiveDetails(archive, active) {
  if (!archive) return "";
  let text = active ? "Importing archive" : "Import incomplete";
  if (archive.imported !== null) {
    const exchanges = archive.imported === 1 ? " exchange " : " exchanges ";
    const warnings = archive.warning_count === 1 ? " warning" : " warnings";
    text = archive.imported + exchanges + (archive.reused ? "reused" : "imported") + " · " + archive.warning_count + warnings;
  }
  return '<p class="statusline">' + esc(archive.name) + ' · ' + esc(text) + '</p>'
    + (archive.sha256 ? '<p class="statusline mono archive-digest">SHA-256 ' + esc(archive.sha256) + '</p>' : '')
    + (archive.warnings?.length ? '<details><summary>Import warnings</summary><ul>'
      + archive.warnings.map(warning => '<li>' + esc(warning) + '</li>').join('') + '</ul></details>' : '');
}
S.tasks = {
  html: '<h1 tabindex="-1">Review tasks</h1><p class="hint">Progress, stop controls, and saved results for passive reviews.</p><div class="toolbar"><button class="go" data-go="scan">New passive review</button>'
    + '<button class="ghost" data-action="tasks.enter">Refresh</button></div><div class="task-list" id="task-list"></div>'
    + '<div class="toolbar" id="task-controls" hidden><button class="ghost" data-action="tasks.cancel" id="cancel-review">Cancel review</button>'
    + '<button class="ghost" data-action="tasks.previous" id="previous-review-results">Previous results</button><button class="ghost" data-action="tasks.next" id="next-review-results">Next results</button></div>'
    + '<div class="toolbar" id="task-report-controls" hidden><label class="sr-only" for="task-report-format">Review report format</label><select id="task-report-format" class="toolbar-select">'
    + '<option value="markdown">Markdown</option><option value="json">JSON</option><option value="html">HTML</option><option value="sarif">SARIF</option></select>'
    + '<button class="ghost" data-action="tasks.report">Export run report</button><button class="ghost" data-action="tasks.bundle">Export evidence bundle</button>'
    + '<span id="task-report-feedback" role="status"></span></div><div class="out" id="o_tasks"></div>',
  selected: null,
  offset: 0,
  nextOffset: null,
  active: false,
  polling: false,
  async enter() {
    if (this.polling) return;
    this.polling = true;
    try {
      const data = await api("review/tasks", {});
      this.active = data.tasks.some(task => ["pending", "running"].includes(task.state));
      const listing = data.tasks.length ? taskLinks(data.tasks) : '<div class="empty"><p>No review runs yet.</p></div>';
      if (listing !== this.lastListing) {
        out("task-list", listing);
        this.lastListing = listing;
      }
      this.selected ??= data.tasks[0]?.id;
      if (this.selected) await this.details();
    } catch (error) { err("o_tasks", error); }
    finally { this.polling = false; }
  },
  async details() {
    const id = this.selected, offset = this.offset;
    const {task, findings, next_offset} = await api("review/task", { id, offset });
    if (id !== this.selected || offset !== this.offset) return;
    this.nextOffset = next_offset;
    const active = ["pending", "running"].includes(task.state);
    $("task-controls").hidden = false;
    $("cancel-review").hidden = !active;
    $("task-report-controls").hidden = active;
    $("previous-review-results").hidden = this.offset === 0;
    $("next-review-results").hidden = next_offset === null;
    const details = '<div class="card"><h3>Passive review #' + esc(task.id) + " " + badge(task.state) + "</h3>"
      + '<progress aria-label="Exchanges examined" max="' + esc(task.limit) + '" value="' + esc(task.examined) + '"></progress><p class="statusline">'
      + esc(task.examined) + " examined · " + esc(task.scanned) + " matched · " + esc(task.findings) + " findings"
      + (task.skipped_large ? " · " + task.skipped_large + " oversized exchanges skipped" : "")
      + (task.omitted ? " · " + task.omitted + " candidates above per-exchange limit" : "")
      + (task.save ? " · Findings saved to triage" : " · Findings kept with the task") + "</p>"
      + (task.workflow ? '<p class="statusline">' + esc(task.workflow.name) + " · Version " + esc(task.workflow.version) + "</p>" : "")
      + archiveDetails(task.archive, active)
      + (task.query ? '<p class="mono">' + esc(task.query) + "</p>" : "")
      + (task.error ? '<p class="err">' + esc(task.error) + "</p>" : "") + "</div>" + findingTable(findings);
    if (this.lastDetails !== details) {
      out("o_tasks", details);
      this.lastDetails = details;
    }
    if (task.archive?.sha256 && !task.archive.reused && this.importRefreshedFor !== id) {
      this.importRefreshedFor = id;
      S.history.result = null;
      S.query.result = null;
    }
  },
  async report() {
    await this.exportFile("report", {format: v("task-report-format")}, "Run report downloaded.");
  },
  async bundle() {
    await this.exportFile("bundle", {}, "Evidence bundle downloaded.");
  },
  async exportFile(kind, options, notice) {
    try {
      const result = await api("review/" + kind, {id: this.selected, ...options});
      download(result.filename, result.content);
      output("task-report-feedback", notice);
    } catch (error) { err("task-report-feedback", error); }
  },
  async cancel() {
    const result = await api("review/cancel", { id: this.selected });
    announce(result.cancelled ? "Review cancelled" : "The review already ended");
    await this.enter();
  },
  async next() { this.offset = this.nextOffset; await this.details(); },
  async previous() { this.offset = Math.max(0, this.offset - 50); await this.details(); }
};

S.workflows = {
  html: '<h1 tabindex="-1">Review workflows</h1><p class="hint">Version a review of stored traffic so you can repeat it with the same filter and limits.</p>'
    + '<div class="card"><div class="row"><div><label for="workflow-select">Saved workflow</label><select id="workflow-select"><option value="">New workflow</option></select></div>'
    + '<div><label for="workflow-version">Version</label><select id="workflow-version" disabled><option value="">New draft</option></select></div></div>'
    + '<div class="row"><div class="grow"><label for="workflow-name">Workflow name</label><input id="workflow-name" maxlength="100" placeholder="Weekly header review"></div>'
    + '<div><label for="workflow-limit">Recent exchanges to examine</label><input id="workflow-limit" type="number" min="1" max="1000" value="200"></div></div>'
    + '<label for="workflow-query">CamioQL filter</label><input id="workflow-query" class="mono" list="query-examples" maxlength="1024" placeholder="Every exchange in the review window">'
    + '<label class="chk"><input type="checkbox" id="workflow-save" checked> Add findings to triage</label>'
    + '<details><summary id="workflow-check-summary">Passive checks</summary><div class="toolbar">'
    + '<button class="ghost" data-action="workflows.selectAllChecks">Select all checks</button><button class="ghost" data-action="workflows.clearChecks">Clear checks</button>'
    + '</div><div class="check-options" id="workflow-check-options"></div></details>'
    + '<label for="workflow-archive">Capture archive (optional)</label><input id="workflow-archive" type="file" accept=".har,.json,.xml,application/json,text/xml,application/xml">'
    + '<p class="statusline" id="workflow-source"></p>'
    + '<ol class="workflow-steps" aria-label="Review steps"><li><strong id="workflow-planned-source">Stored traffic</strong><small id="workflow-planned-limit"></small></li>'
    + '<li><strong>CamioQL filter</strong><small id="workflow-planned-query"></small></li><li><strong>Passive checks</strong><small id="workflow-planned-checks">All built-in checks</small></li>'
    + '<li><strong>Findings</strong><small id="workflow-planned-output"></small></li></ol>'
    + '<div class="toolbar"><button class="go" data-action="workflows.save">Save workflow version</button>'
    + '<button class="ghost" id="workflow-run" data-action="workflows.run" disabled>Run saved version</button><button class="ghost" id="workflow-clear-archive" data-action="workflows.clearArchive" hidden>Clear archive</button><span id="workflow-state" class="statusline" role="status"></span></div>'
    + '<details><summary>Plan JSON</summary><label for="workflow-json">Plan document</label><textarea id="workflow-json" class="tall" spellcheck="false"></textarea>'
    + '<div class="toolbar"><button class="ghost" data-action="workflows.applyJson">Apply JSON to draft</button>'
    + '<button class="ghost" data-action="workflows.download">Download plan JSON</button></div></details></div><div id="o_workflows"></div>',
  saved: null,
  availableChecks: [],
  checkIds: null,
  jsonDirty: false,
  selectionRequest: 0,
  async enter() {
    try {
      const [, catalog] = await Promise.all([this.list(), api("review/checks", {})]);
      this.availableChecks = catalog.checks;
      this.renderChecks();
      this.sync();
    } catch (error) { err("o_workflows", error); }
  },
  async list() {
    const {workflows} = await api("workflows", {});
    const select = $("workflow-select");
    select.replaceChildren(new Option("New workflow", ""));
    for (const flow of workflows) select.add(new Option(flow.name, String(flow.id)));
    select.value = this.saved ? String(this.saved.id) : "";
  },
  async select(id, version) {
    const request = ++this.selectionRequest;
    try {
      if (!id) this.populate(null, []);
      else {
        const data = await api("workflows/get", {id: Number(id), version: version ? Number(version) : null});
        if (request !== this.selectionRequest) return;
        this.populate(data.workflow, data.versions);
      }
      out("o_workflows", "");
    } catch (error) { if (request === this.selectionRequest) err("o_workflows", error); }
  },
  populate(workflow, versions) {
    this.saved = workflow;
    this.jsonDirty = false;
    const plan = workflow?.plan || {query: "", limit: 200, save: true};
    this.checkIds = plan.check_ids ?? null;
    $("workflow-name").value = workflow?.name || "";
    $("workflow-query").value = plan.query;
    $("workflow-limit").value = plan.limit;
    $("workflow-save").checked = plan.save;
    const select = $("workflow-version");
    select.replaceChildren();
    for (const revision of versions) select.add(new Option("Version " + revision.version, String(revision.version)));
    if (!workflow) select.add(new Option("New draft", ""));
    else select.value = String(workflow.version);
    select.disabled = !workflow;
    $("workflow-select").value = workflow ? String(workflow.id) : "";
    this.renderChecks();
    this.sync();
  },
  plan() {
    const draft = {schema_version: this.checkIds === null ? 1 : 2, query: v("workflow-query").trim(),
      limit: Number(v("workflow-limit")), save: ck("workflow-save")};
    if (this.checkIds !== null) draft.check_ids = [...this.checkIds].sort();
    return draft;
  },
  isSaved(plan) {
    return !this.jsonDirty && this.saved?.name === v("workflow-name").trim() && this.saved.plan.query === plan.query
      && this.saved.plan.limit === plan.limit && this.saved.plan.save === plan.save
      && this.saved.plan.schema_version === plan.schema_version
      && JSON.stringify(this.saved.plan.check_ids) === JSON.stringify(plan.check_ids);
  },
  sync() {
    const plan = this.plan();
    const saved = this.isSaved(plan);
    const archive = $("workflow-archive").files[0];
    output("workflow-source", archive ? "Review input · " + archive.name : "Review input · Stored history");
    output("workflow-planned-source", archive ? "Import capture" : "Stored traffic");
    $("workflow-clear-archive").hidden = !archive;
    output("workflow-planned-limit", plan.limit > 0 ? "Up to " + plan.limit + " exchanges" : "Choose an exchange limit");
    output("workflow-planned-query", plan.query || "All in review window");
    const checkCount = this.checkIds?.length ?? this.availableChecks.length;
    output("workflow-check-summary", "Passive checks · " + checkCount + " selected");
    output("workflow-planned-checks", this.checkIds === null ? "All built-in checks" : checkCount + " selected");
    output("workflow-planned-output", plan.save ? "Save to triage" : "Keep in task results");
    output("workflow-state", this.jsonDirty ? "Apply JSON edits to the draft" : saved ? "Saved version " + this.saved.version
      : this.checkIds?.length === 0 ? "Select a passive check" : "Draft");
    output("workflow-run", saved ? "Run version " + this.saved.version + (archive ? " on archive" : "") : "Run saved version");
    $("workflow-run").disabled = !saved;
    if (!this.jsonDirty) $("workflow-json").value = JSON.stringify(plan, null, 2);
  },
  renderChecks() {
    out("workflow-check-options", this.availableChecks.map(check => '<label class="chk">'
      + '<input type="checkbox" data-review-check value="' + esc(check.id) + '"'
      + (this.checkIds === null || this.checkIds.includes(check.id) ? " checked" : "")
      + '>' + esc(check.title) + '</label>').join(""));
  },
  selectAllChecks() { this.checkIds = null; this.renderChecks(); this.sync(); },
  clearChecks() { this.checkIds = []; this.renderChecks(); this.sync(); },
  changeChecks() {
    const selected = Array.from($("workflow-check-options").querySelectorAll("input:checked"), element => element.value);
    this.checkIds = selected.length === this.availableChecks.length ? null : selected;
    this.sync();
  },
  applyJson() {
    const plan = JSON.parse(v("workflow-json"));
    const fields = plan?.schema_version === 1 ? "limit,query,save,schema_version" : "check_ids,limit,query,save,schema_version";
    if (!plan || ![1, 2].includes(plan.schema_version) || typeof plan.query !== "string" || typeof plan.save !== "boolean"
      || !Number.isInteger(plan.limit) || plan.limit < 1 || plan.limit > 1000 || Object.keys(plan).sort().join(",") !== fields) {
      throw new Error("Use a version 1 plan or a version 2 plan with check_ids.");
    }
    if (plan.schema_version === 2 && (!Array.isArray(plan.check_ids) || !plan.check_ids.length
      || new Set(plan.check_ids).size !== plan.check_ids.length
      || !plan.check_ids.every(id => this.availableChecks.some(check => check.id === id)))) {
      throw new Error("Choose one or more distinct passive check IDs from the catalog.");
    }
    $("workflow-query").value = plan.query;
    $("workflow-limit").value = plan.limit;
    $("workflow-save").checked = plan.save;
    this.checkIds = plan.check_ids ?? null;
    this.jsonDirty = false;
    this.renderChecks();
    this.sync();
    out("o_workflows", "");
    announce("JSON plan applied to the draft");
  },
  download() {
    download("camio-review-plan.json", v("workflow-json") + "\n");
  },
  clearArchive() {
    $("workflow-archive").value = "";
    this.sync();
  },
  async save() {
    if (this.jsonDirty) throw new Error("Apply JSON edits to the draft before saving.");
    const data = await api("workflows/save", {name: v("workflow-name"), plan: this.plan()});
    this.saved = data.workflow;
    await this.list();
    this.populate(data.workflow, data.versions);
    out("o_workflows", "");
    announce("Saved workflow version " + data.workflow.version);
  },
  async run() {
    if (!this.isSaved(this.plan())) throw new Error("Save the draft before running it.");
    const file = $("workflow-archive").files[0];
    const args = {id: this.saved.id, version: this.saved.version};
    if (file) args.archive = {name: file.name, content: await selectedText("workflow-archive", null)};
    const {id} = await api("workflows/start", args);
    S.tasks.selected = id;
    S.tasks.offset = 0;
    show("tasks");
    announce("Started review " + id);
  }
};

S.findings = {
  html: '<h1 tabindex="-1">Findings</h1><p class="hint">Review severity, notes, and linked exchanges.</p>'
    + '<div class="toolbar"><label for="f_state">Status</label><select class="toolbar-select" id="f_state">' + stateOptions(null, true) + '</select>'
    + '<button class="ghost" data-action="findings.reset">Filter</button><span class="spacer"></span><label class="sr-only" for="report-format">Report format</label>'
    + '<select id="report-format" class="toolbar-select"><option value="markdown">Markdown</option><option value="json">JSON</option><option value="html">HTML</option><option value="sarif">SARIF</option></select>'
    + '<button class="ghost" data-action="findings.report">Export report</button></div><div id="finding-editor" hidden></div><div id="o_findings"></div>',
  rows: [],
  offset: 0,
  async enter() { await this.load(); },
  async reset() { this.offset = 0; await this.load(); },
  async next() { this.offset += 50; await this.load(); },
  async previous() { this.offset = Math.max(0, this.offset - 50); await this.load(); },
  async load() {
    out("o_findings", loading);
    try {
      const data = await api("findings", { state: v("f_state") || null, offset: this.offset });
      this.rows = data.findings;
      out("o_findings", findingTable(this.rows) + '<div class="toolbar">'
        + (this.offset ? button("Previous", 'data-action="findings.previous"') : "")
        + (data.next_offset ? button("Next", 'data-action="findings.next"') : "") + "</div>");
    } catch (error) { err("o_findings", error); }
  },
  edit(id) {
    const finding = this.rows.find(row => row.id === id);
    if (!finding) return;
    this.selected = id;
    $("finding-editor").hidden = false;
    out("finding-editor", '<div class="card"><h3>Triage #' + esc(id) + " · " + esc(finding.title) + '</h3><label for="edit-state">Status</label>'
      + '<select id="edit-state">' + stateOptions(finding.state) + '</select><label for="edit-note">Review notes</label><textarea id="edit-note" maxlength="4096">'
      + esc(finding.note) + '</textarea><div class="toolbar"><button class="go" data-action="findings.save">Save triage</button><button class="ghost" data-action="findings.close">Close</button></div><div id="triage-status" role="status"></div></div>');
    $("edit-state").focus();
  },
  close() { $("finding-editor").hidden = true; this.selected = null; },
  async save() {
    await api("findings/review", { id: this.selected, state: v("edit-state"), note: v("edit-note") });
    output("triage-status", "Triage saved.");
    await this.load();
  },
  async report() {
    const report = await api("findings/report", { state: v("f_state") || null, format: v("report-format") });
    download(report.filename, report.content);
  }
};

S.import = {
  html: '<h1 tabindex="-1">Import traffic</h1><p class="hint">Preview a HAR or Burp items XML archive before adding its exchanges to this workspace.</p>'
    + '<div class="card"><label for="im_file">Archive file</label><input type="file" id="im_file" accept=".har,.json,.xml,application/json,text/xml,application/xml">'
    + '<label for="im_content">Or paste archive contents</label><textarea class="tall" id="im_content"></textarea>'
    + '<div class="toolbar"><button class="ghost" data-action="import.preview">Preview archive</button><button class="go" data-action="import.save">Import exchanges</button></div></div><div class="out" id="o_import"></div>',
  async submit(save) {
    try {
      const content = await selectedText("im_file", "im_content");
      out("o_import", loading);
      const result = await api("import", { content, save });
      out("o_import", '<div class="card"><h3>' + esc(result.format) + " · " + esc(result.imported) + " exchanges</h3><p>" + (save ? result.stored + " stored" : "Preview")
        + "</p>" + (result.warnings.length ? "<ul>" + result.warnings.map(warning => "<li>" + esc(warning) + "</li>").join("") + "</ul>" : "") + "</div>");
      if (save) { S.history.result = null; S.query.result = null; }
      announce(save ? result.stored + " exchanges imported" : "Archive preview loaded");
    } catch (error) { err("o_import", error); }
  },
  async preview() { await this.submit(false); },
  async save() { await this.submit(true); }
};

function observationTable(records) {
  if (!records.length) return '<p class="hint">No structured observations for this file.</p>';
  return '<div class="tablewrap"><table><thead><tr><th>Line</th><th>Observed location</th><th>Result</th><th>Metadata</th></tr></thead><tbody>'
    + records.map(row => "<tr><td>" + esc(row.line) + '</td><td class="mono">' + esc(row.location) + "</td><td>"
      + esc([row.status, row.severity, row.outcome].filter(Boolean).join(" · ")) + "</td><td>"
      + esc([row.title, row.template, row.matcher, row.server, row.content_type,
        row.content_length === null ? null : bytes(row.content_length), ...(row.technologies || [])].filter(Boolean).join(" · "))
      + "</td></tr>").join("") + "</tbody></table></div>";
}
S.integrations = {
  html: '<h1 tabindex="-1">Integration evidence</h1><p class="hint">Import previously collected httpx and Nuclei JSONL. Keep other tool reports as raw text.</p>'
    + '<div class="card"><div class="row"><div><label for="tool-format">Format</label><select id="tool-format"><option value="httpx">ProjectDiscovery httpx JSONL</option>'
    + '<option value="nuclei">Nuclei JSONL</option><option value="raw">Raw evidence (text)</option></select></div>'
    + '<div><label for="tool-version">Tool version (optional)</label><input id="tool-version" maxlength="120"></div></div>'
    + '<label for="tool-file">Evidence file</label><input type="file" id="tool-file"><label for="tool-content">Or paste evidence</label><textarea id="tool-content"></textarea>'
    + '<div class="toolbar"><button class="ghost" data-action="integrations.preview">Preview evidence</button><button class="go" data-action="integrations.save">Store evidence</button></div></div>'
    + '<div class="out" id="o_integrations"></div><div class="out" id="artifact-list"></div><div class="out" id="artifact-details"></div>',
  selected: null,
  cursor: null,
  before: null,
  async enter() {
    try { await this.list(); } catch (error) { err("artifact-list", error); }
  },
  async submit(save) {
    const content = await selectedText("tool-file", "tool-content");
    out("o_integrations", loading);
    const result = await api("artifacts/import", { format: v("tool-format"), version: v("tool-version") || null, content, save });
    out("o_integrations", '<div class="card"><h3>' + esc(titleCase(result.format)) + " evidence</h3><p>" + result.records + " records · " + result.skipped + " skipped"
      + (result.existing ? " · Already stored" : result.artifact_id ? " · Stored" : " · Preview") + '</p><p class="mono hint">SHA-256 ' + esc(result.sha256) + "</p>"
      + (result.warnings.length ? "<ul>" + result.warnings.map(warning => "<li>" + esc(warning) + "</li>").join("") + "</ul>" : "")
      + (result.sample.length ? observationTable(result.sample) : "") + "</div>");
    if (save) { this.before = null; await this.list(); }
  },
  async preview() { await this.submit(false); },
  async save() { await this.submit(true); },
  async list() {
    const result = await api("artifacts", { before: this.before });
    this.next = result.next_before;
    out("artifact-list", '<div class="panel"><div class="panel-head"><h2>Stored artifacts</h2></div>'
      + (result.artifacts.length
        ? '<div class="tablewrap"><table><thead><tr><th>ID</th><th>Source</th><th>Version</th><th>Records</th><th>Skipped</th></tr></thead><tbody>'
          + result.artifacts.map(row => "<tr><td>" + button("Artifact #" + row.id, 'data-artifact="' + esc(row.id) + '"', "text-button")
            + "</td><td>" + esc(titleCase(row.format)) + "</td><td>" + esc(row.version || "Unknown")
            + "</td><td>" + row.records + "</td><td>" + row.skipped + "</td></tr>").join("") + "</tbody></table></div>"
        : '<div class="empty">No artifacts on this page.</div>') + '</div><div class="toolbar">'
      + (this.before ? button("Newest artifacts", 'data-action="integrations.newest"') : "") + (this.next ? button("Older artifacts", 'data-action="integrations.older"') : "") + "</div>");
  },
  async newest() { this.before = null; await this.list(); },
  async older() { this.before = this.next; await this.list(); },
  async open(id) {
    this.selected = id;
    this.cursor = null;
    await this.details();
    $("artifact-details").scrollIntoView({ block: "nearest" });
  },
  async details() {
    const result = await api("artifacts/observations", { id: this.selected, before: this.cursor });
    this.nextObservation = result.next_before;
    out("artifact-details", '<div class="card"><h3>Artifact #' + esc(this.selected) + '</h3><div class="toolbar">'
      + button("Download original", 'data-action="integrations.raw"')
      + (this.cursor ? button("Newest observations", 'data-action="integrations.latestObservations"') : "")
      + (result.next_before ? button("Older observations", 'data-action="integrations.moreObservations"') : "")
      + "</div>" + observationTable(result.observations) + "</div>");
  },
  async latestObservations() { this.cursor = null; await this.details(); },
  async moreObservations() { this.cursor = this.nextObservation; await this.details(); },
  async raw() {
    const original = await api("artifacts/raw", { id: this.selected });
    download("camio-artifact-" + this.selected + ".txt", original.content);
  }
};

function inventoryTable(rows, endpoints) {
  if (!rows.length) return '<div class="empty">No recorded ' + (endpoints ? "endpoints" : "assets") + " on this page.</div>";
  return '<div class="tablewrap"><table><thead><tr><th scope="col">' + (endpoints ? "Endpoint" : "Origin")
    + '</th><th scope="col">Captured</th><th scope="col">httpx</th><th scope="col">Nuclei</th><th scope="col">Last recorded</th></tr></thead><tbody>'
    + rows.map(row => {
      const value = endpoints ? row.location : row.origin;
      const action = endpoints ? 'data-asset-endpoint' : 'data-asset-origin';
      return '<tr><td><span class="mono">' + button(value, action + '="' + esc(value) + '"', "text-button")
        + '</span>' + (row.label ? '<small class="inventory-label">' + esc(row.label) + '</small>' : "")
        + (!endpoints ? '<small class="inventory-label">' + row.endpoints + (row.endpoints === 1 ? " endpoint" : " endpoints") + "</small>" : "")
        + "</td><td>" + esc(row.captured) + "</td><td>" + esc(row.httpx) + "</td><td>" + esc(row.nuclei)
        + '</td><td class="mono">' + esc(new Date(row.last_seen_at_ms).toLocaleString()) + "</td></tr>";
    }).join("") + "</tbody></table></div>";
}

S.inventory = {
  html: '<div class="inventory-banner"><div class="hero-grid" aria-hidden="true"></div><div class="inventory-banner-copy">'
    + '<h1 tabindex="-1">Asset inventory</h1><p class="hint">Captured traffic and imported observations grouped by origin.</p></div></div>'
    + '<div class="toolbar"><label for="asset-filter" class="sr-only">Filter origins</label><input class="mono inventory-filter" id="asset-filter" type="search" maxlength="256" placeholder="Filter origins">'
    + '<button class="go" id="asset-search" data-action="inventory.search">Filter</button><button class="ghost" data-action="inventory.enter">Refresh</button></div>'
    + '<div class="panel inventory-panel" id="inventory-list"></div><div id="o_inventory"></div>'
    + '<div class="out" id="inventory-asset"></div><div class="out" id="inventory-notes"></div><div class="out" id="inventory-evidence"></div>',
  filter: "",
  cursors: [null],
  next: null,
  origin: null,
  endpointAfter: null,
  nextEndpoint: null,
  endpoint: null,
  evidenceBefore: null,
  nextEvidence: null,
  selectionId: 0,
  async enter() {
    try { await this.list(); }
    catch (error) { err("o_inventory", error); }
  },
  async search() {
    this.filter = v("asset-filter").trim();
    this.cursors = [null];
    await this.list();
  },
  async list() {
    const page = await api("inventory", {filter: this.filter, after: this.cursors.at(-1)});
    this.next = page.next_after;
    out("inventory-list", '<div class="panel-head"><h2>Origins</h2><div class="inline">'
      + (this.cursors.length > 1 ? button("Previous", 'data-action="inventory.previous"') : "")
      + (this.next ? button("Next", 'data-action="inventory.older"') : "")
      + '</div></div>' + inventoryTable(page.assets, false));
    out("o_inventory", "");
  },
  async previous() { this.cursors.pop(); await this.list(); },
  async older() { this.cursors.push(this.next); await this.list(); },
  async open(origin) {
    this.origin = origin;
    this.endpointAfter = null;
    this.endpoint = null;
    out("inventory-asset", loading);
    out("inventory-evidence", "");
    out("inventory-notes", "");
    await this.asset(true);
    $("inventory-asset").scrollIntoView({block: "nearest"});
  },
  async asset(resetNotes = false) {
    const request = ++this.selectionId;
    const result = await api("inventory/asset", {origin: this.origin, after: this.endpointAfter});
    if (request !== this.selectionId) return;
    const {asset, note, endpoints, next_after} = result;
    this.nextEndpoint = next_after;
    out("inventory-asset", '<div class="panel inventory-panel"><div class="panel-head"><div><h2>Endpoints</h2>'
      + '<span class="mono inventory-location">' + esc(asset.origin) + '</span></div><div class="inline">'
      + (this.endpointAfter ? button("First endpoints", 'data-action="inventory.firstEndpoints"') : "")
      + (this.nextEndpoint ? button("More endpoints", 'data-action="inventory.moreEndpoints"') : "")
      + '</div></div>' + inventoryTable(endpoints, true) + '</div>');
    if (resetNotes) {
      out("inventory-notes", '<div class="card"><details><summary>Asset notes</summary><label for="asset-label">Label</label>'
        + '<input id="asset-label" maxlength="120" value="' + esc(note.label) + '"><label for="asset-note">Note</label>'
        + '<textarea id="asset-note" maxlength="4096">' + esc(note.note) + '</textarea>'
        + '<div class="toolbar"><button class="go" data-action="inventory.saveNote">Save asset note</button><span id="asset-note-status" role="status"></span></div>'
        + '</details></div>');
    }
  },
  async firstEndpoints() { this.endpointAfter = null; await this.asset(); },
  async moreEndpoints() { this.endpointAfter = this.nextEndpoint; await this.asset(); },
  async saveNote() {
    const origin = this.origin;
    try {
      await api("inventory/note", {origin, label: v("asset-label"), note: v("asset-note")});
      if (origin === this.origin) output("asset-note-status", "Asset note saved.");
      await this.list();
    } catch (error) { err("asset-note-status", error); }
  },
  async selectEndpoint(location) {
    this.endpoint = location;
    this.evidenceBefore = null;
    await this.evidence();
    $("inventory-evidence").scrollIntoView({block: "nearest"});
  },
  async firstEvidence() { this.evidenceBefore = null; await this.evidence(); },
  async moreEvidence() { this.evidenceBefore = this.nextEvidence; await this.evidence(); },
  async evidence() {
    const endpoint = this.endpoint;
    const page = await api("inventory/evidence", {location: endpoint, before: this.evidenceBefore});
    if (endpoint !== this.endpoint) return;
    this.nextEvidence = page.next_before;
    const rows = page.records.map(record => {
      const link = record.exchange_id
        ? button("Exchange #" + record.exchange_id, 'data-exchange="' + esc(record.exchange_id) + '"', "text-button")
        : button("Artifact #" + record.artifact_id + " · Line " + record.line, 'data-inventory-artifact="' + esc(record.artifact_id) + '"', "text-button");
      return "<tr><td>" + link + '</td><td><span class="badge">' + esc(record.source) + "</span></td><td>"
        + esc([record.status, record.outcome, record.description].filter(Boolean).join(" · ") || "—") + "</td></tr>";
    }).join("");
    out("inventory-evidence", '<div class="panel inventory-panel"><div class="panel-head"><div><h2>Endpoint evidence</h2><span class="mono inventory-location">'
      + esc(page.location) + '</span></div><div class="inline">'
      + (this.evidenceBefore ? button("Newest evidence", 'data-action="inventory.firstEvidence"') : "")
      + (this.nextEvidence ? button("Older evidence", 'data-action="inventory.moreEvidence"') : "")
      + '</div></div>' + (rows
        ? '<div class="tablewrap"><table><thead><tr><th scope="col">Source record</th><th scope="col">Type</th><th scope="col">Observation</th></tr></thead><tbody>'
          + rows + "</tbody></table></div>"
        : '<div class="empty">No evidence on this page.</div>') + "</div>");
  }
};

S.library = {
  html: '<h1 tabindex="-1">Library</h1><p class="hint">Return to saved exchanges and CamioQL searches.</p><div id="o_library"></div>',
  offset: 0,
  async enter() {
    try {
      const data = await api("library", { offset: this.offset });
      out("o_library", '<div class="panel"><div class="panel-head"><h2>Saved exchanges</h2></div>' + (data.exchanges.length
        ? '<div class="tablewrap"><table><thead><tr><th>Exchange</th><th>Label</th><th>Notes</th><th>URL</th></tr></thead><tbody>'
          + data.exchanges.map(item => "<tr><td>" + button("#" + item.id, 'data-exchange="' + esc(item.id) + '"', "text-button")
            + "</td><td>" + esc(item.label || "—") + "</td><td>" + esc(item.note || "—") + '</td><td class="mono">' + esc(item.url) + "</td></tr>").join("")
          + "</tbody></table></div>" : '<div class="empty">Save an exchange from its inspector to see it here.</div>') + '</div><div class="toolbar">'
        + (this.offset ? button("Previous", 'data-action="library.previous"') : "") + (data.next_offset ? button("Next", 'data-action="library.next"') : "")
        + '</div><div class="panel"><div class="panel-head"><h2>Saved queries</h2></div><div class="panel-body">'
        + (data.queries.length ? data.queries.map(item => '<div class="toolbar"><span>' + esc(item.name) + '</span><code>' + esc(item.expression)
          + '</code><span class="spacer"></span>' + button("Run", 'data-query="' + esc(item.expression) + '"') + button("Remove", 'data-delete-query="' + esc(item.name) + '"') + "</div>").join("")
          : '<p class="hint">Save filters from the History or CamioQL view.</p>') + "</div></div>");
    } catch (error) { err("o_library", error); }
  },
  async previous() { this.offset = Math.max(0, this.offset - 100); await this.enter(); },
  async next() { this.offset += 100; await this.enter(); },
  async remove(name) {
    await api("queries/delete", {name});
    announce("Removed saved query " + name);
    await this.enter();
  }
};

S.comparer = {
  html: '<h1 tabindex="-1">Comparer</h1><p class="hint">Compare two local messages by bytes and lines.</p><div class="files"><div><label for="cmp-a">Message A</label>'
    + '<textarea class="tall" id="cmp-a"></textarea></div><div><label for="cmp-b">Message B</label><textarea class="tall" id="cmp-b"></textarea></div></div>'
    + '<button class="go" data-action="comparer.run">Compare</button><div class="out" id="o_comparer"></div>',
  async run() {
    const diff = await api("compare", {a:v("cmp-a"),b:v("cmp-b")});
    const lineBreak = String.fromCharCode(10);
    const lines = diff.lines.split(lineBreak).map(line => {
      const style = line.startsWith("+") ? "diff-insert" : line.startsWith("-") ? "diff-delete" : "";
      return '<span class="' + style + '">' + esc(line) + "</span>";
    }).join(lineBreak);
    out("o_comparer", '<p class="statusline">' + (diff.bytes.equal ? "Identical" : "First difference at byte " + diff.bytes.first_diff_offset)
      + " · A " + esc(bytes(diff.bytes.a_len)) + " · B " + esc(bytes(diff.bytes.b_len)) + '</p><pre class="out">' + (lines.trim() ? lines : "No line changes.") + "</pre>");
  }
};
S.analyze = {
  html: '<h1 tabindex="-1">Analyze JavaScript</h1><p class="hint">Inspect local source for secret categories and referenced paths.</p>'
    + '<label for="js-source">JavaScript source</label><textarea class="tall" id="js-source"></textarea><button class="go" data-action="analyze.run">Analyze source</button><div class="out" id="o_analyze"></div>',
  async run() {
    const result = await api("analyze-js", { code: v("js-source") });
    const items = values => values.length ? "<ul>" + values.map(value => "<li>" + esc(value) + "</li>").join("") + "</ul>" : '<p class="hint">None detected.</p>';
    out("o_analyze", '<div class="card"><h3>Secret categories</h3>' + items(result.secrets) + '<h3>Referenced paths</h3>' + items(result.endpoints) + "</div>");
  }
};

function detailRows(rows) {
  return rows.map(([label, value]) => "<dt>" + esc(label) + "</dt><dd>" + esc(value ?? "—") + "</dd>").join("");
}
S.fingerprint = {
  html: '<h1 tabindex="-1">Request transport</h1><p class="hint">Configured profile and transport metadata for the local engine.</p><div class="card" id="o_fingerprint"></div>',
  enter() {
    if (!meta) return;
    out("o_fingerprint", '<dl class="kv">' + detailRows([
      ["Profile", meta.profile], ["Camoufox build", meta.camoufox_build], ["Engine", meta.engine], ["Fingerprint target", meta.fingerprint_target],
      ["Emulation", meta.fingerprint_matched ? "Configured" : "Dry run"], ["Measured parity", "Unverified"], ["User agent", meta.user_agent]
    ]) + "</dl>" + (meta.parity_note ? '<p class="notice">' + esc(meta.parity_note) + "</p>" : ""));
  }
};
S.settings = {
  html: '<h1 tabindex="-1">Workspace settings</h1><div class="card"><h3>Project</h3><label for="workspace-input">Workspace name</label>'
    + '<input id="workspace-input" maxlength="120"><button class="go" data-action="settings.rename">Save name</button><div class="out" id="o_settings"></div></div>'
    + '<div class="card"><h3>Interface</h3><label class="chk"><input id="reduce-motion" type="checkbox"> Reduce motion</label></div>'
    + '<div class="card"><h3>Local store</h3><div class="mono" id="settings-db">Connecting…</div></div>',
  async enter() {
    $("reduce-motion").checked = document.documentElement.dataset.motion === "reduced";
    if (meta) output("settings-db", meta.db);
    if (!workspace) {
      try { setWorkspace((await api("workspace", {})).workspace); } catch (error) { err("o_settings", error); }
    } else if (!v("workspace-input")) {
      $("workspace-input").value = workspace.project.name;
    }
  },
  async rename() {
    await api("workspace/rename", {name:v("workspace-input")});
    setWorkspace((await api("workspace", {})).workspace);
    output("o_settings", "Workspace name saved.");
  }
};

const VERSIONS = { http10:"HTTP/1.0", http11:"HTTP/1.1", h2:"HTTP/2", h3:"HTTP/3" };
function showMessage() {
  if (!inspector?.preview) return;
  const {exchange, req_len, resp_len} = inspector.preview;
  const isRequest = v("message-side") === "request";
  const message = isRequest ? exchange.request : exchange.response;
  const target = $("message-output");
  if (!message) {
    target.replaceChildren();
    target.textContent = "This exchange has no stored response.";
    output("message-bytes", "");
    return;
  }
  const buffer = Uint8Array.from(atob(message.body || ""), character => character.charCodeAt(0));
  const count = isRequest ? req_len : resp_len;
  output("message-bytes", buffer.length < count ? "Showing " + bytes(buffer.length) + " of " + bytes(count) : bytes(count));
  const version = VERSIONS[message.version] || message.version || "";
  const start = isRequest ? message.method + " " + message.url + " " + version : [version, message.status, message.reason].filter(Boolean).join(" ");
  const headers = (message.headers || []).map(({name,value}) => [name, value]);
  const view = v("message-view");
  if (view === "structured") {
    out("message-output", "<p class=\"mono inspector-subtitle\">" + esc(start) + "</p>"
      + (headers.length ? '<div class="tablewrap"><table aria-label="Stored headers"><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody>'
        + headers.map(([name, value]) => '<tr><td class="mono">' + esc(name) + '</td><td class="mono">' + esc(value) + "</td></tr>").join("")
        + "</tbody></table></div>" : '<p class="hint">No stored headers.</p>')
      + '<pre class="message-preview" id="message-body"></pre>');
    output("message-body", new TextDecoder().decode(buffer) || "(empty body)");
  } else {
    let text;
    if (view === "hex") {
      const lines = [];
      for (let index = 0; index < buffer.length; index += 16) {
        const value = Array.from(buffer.slice(index, index + 16), byte => byte.toString(16).padStart(2, "0")).join(" ");
        lines.push(index.toString(16).padStart(6, "0") + "  " + value);
      }
      text = lines.join("\n") || "(empty body)";
    } else {
      text = [start, ...headers.map(parts => parts.join(": ")), "", new TextDecoder().decode(buffer)].join("\r\n");
    }
    out("message-output", '<pre class="message-preview" id="message-body"></pre>');
    output("message-body", text);
  }
}
async function inspect(id) {
  const dialog = $("inspector");
  const selection = {id};
  inspector = selection;
  if (!dialog.open) dialog.showModal();
  output("inspector-title", "Exchange #" + id);
  out("inspector-content", loading);
  try {
    const result = await api("exchange", {id});
    if (inspector !== selection) return;
    Object.assign(inspector, result);
    const {exchange} = result.preview;
    out("inspector-content", '<p class="mono inspector-subtitle">' + esc(exchange.request.method) + " " + esc(exchange.request.url) + '</p>'
      + '<div class="row"><div><label for="message-side">Message</label><select id="message-side"><option value="request">Request</option>'
      + (exchange.response ? '<option value="response">Response</option>' : "") + '</select></div>'
      + '<div><label for="message-view">View</label><select id="message-view"><option value="structured">Structured</option><option value="raw">Reconstructed raw</option>'
      + '<option value="hex">Body hex</option></select></div></div><p class="statusline" id="message-bytes"></p><div id="message-output"></div>'
      + '<details><summary>Save to library</summary><label for="bookmark-label">Label</label><input id="bookmark-label" maxlength="120" value="' + esc(result.saved?.label)
      + '"><label for="bookmark-note">Notes</label><textarea class="compact" id="bookmark-note" maxlength="4096">'
      + esc(result.saved?.note) + '</textarea><div class="toolbar"><button class="go" data-bookmark="save">Save exchange</button>'
      + '<button class="ghost" data-bookmark="delete"' + (result.saved ? "" : " hidden") + '>Remove saved exchange</button></div><div id="bookmark-status" role="status"></div></details>');
    showMessage();
  } catch (error) { err("inspector-content", error); }
}
async function bookmark(action) {
  const id = inspector.id;
  const payload = {id};
  if (action === "save") Object.assign(payload, {label:v("bookmark-label"), note:v("bookmark-note")});
  await api("library/" + action, payload);
  output("bookmark-status", action === "save" ? "Saved to the library." : "Removed from the library.");
  document.querySelector('[data-bookmark="delete"]').hidden = action !== "save";
  if (current === "library") await S.library.enter();
}

function show(id, { push = true, focus = true, enter = true } = {}) {
  if (!Object.hasOwn(S, id)) return;
  const switched = current !== id;
  current = id;
  for (const section of $("panels").children) section.hidden = section.id !== "sec_" + id;
  for (const entry of $("nav").querySelectorAll("button")) {
    if (entry.dataset.go === id) entry.setAttribute("aria-current", "page");
    else entry.removeAttribute("aria-current");
  }
  output("current-page", LABELS[id]);
  document.title = LABELS[id] + " · Camio";
  let section = $("sec_" + id);
  if (!section) {
    section = document.createElement("section");
    section.className = "surface section-shell" + (["status", "history", "query", "tasks", "findings", "inventory"].includes(id) ? " wide-view" : "");
    section.id = "sec_" + id;
    section.innerHTML = S[id].html;
    $("panels").appendChild(section);
  }
  section.hidden = false;
  if (push && switched) history.pushState(null, "", "#" + id);
  if (switched) {
    for (const checkbox of [$('r_c'), $('f_c')]) {
      if (checkbox) checkbox.checked = false;
    }
    window.scrollTo(0, 0);
  }
  if (focus) {
    const heading = section.querySelector("h1, h2");
    if (heading) { heading.tabIndex = -1; heading.focus({preventScroll:true}); }
  }
  $("rail").classList.remove("is-open");
  $("nav-toggle").setAttribute("aria-expanded", "false");
  if (enter && S[id].enter) S[id].enter();
}
function searchTools() {
  const query = v("tool-search").trim().toLowerCase();
  const tools = TOOLS.filter(([id, label]) => (label + " " + id).toLowerCase().includes(query));
  out("tool-results", tools.length ? tools.map(([id, label]) => button(label, 'data-go="' + id + '"')).join("") : '<p class="hint">No tools match.</p>');
}
function openSearch() {
  const dialog = $("command-menu");
  if (dialog.open || $("inspector").open) return;
  $("tool-search").value = "";
  searchTools();
  dialog.showModal();
  $("tool-search").focus();
}

async function act(target, run, errorId) {
  target.disabled = true;
  try { await run(); }
  catch (error) { err(errorId, error); announce(error.message || String(error)); }
  finally { target.disabled = false; }
}
document.addEventListener("click", event => {
  const target = event.target.closest("button");
  if (!target) return;
  const data = target.dataset;
  if (data.go) {
    if ($("command-menu").open) $("command-menu").close();
    show(data.go);
  } else if (data.close) {
    $(data.close).close();
  } else if (data.action) {
    const [view, method] = data.action.split(".");
    const handler = S[view];
    if (handler && Object.hasOwn(handler, method) && typeof handler[method] === "function") {
      act(target, () => handler[method](), view === "findings" && method === "save" ? "triage-status" : "o_" + view);
    }
  } else if (data.exchange) {
    inspect(Number(data.exchange));
  } else if (data.task) {
    S.tasks.selected = Number(data.task);
    S.tasks.offset = 0;
    if (current === "tasks") act(target, () => S.tasks.details(), "o_tasks");
    else show("tasks");
  } else if (data.finding) {
    S.findings.edit(Number(data.finding));
  } else if (data.bookmark) {
    act(target, () => bookmark(data.bookmark), "bookmark-status");
  } else if (data.sort && S[current]?.result) {
    const surface = S[current];
    surface.sort = { key: data.sort, asc: surface.sort.key !== data.sort || !surface.sort.asc };
    surface.render();
    $("o_" + current).querySelector('[data-sort="' + data.sort + '"]')?.focus();
  } else if (data.artifact) {
    act(target, () => S.integrations.open(Number(data.artifact)), "artifact-details");
  } else if (data.assetOrigin) {
    act(target, () => S.inventory.open(data.assetOrigin), "inventory-asset");
  } else if (data.assetEndpoint) {
    act(target, () => S.inventory.selectEndpoint(data.assetEndpoint), "inventory-evidence");
  } else if (data.inventoryArtifact) {
    show("integrations");
    act(target, () => S.integrations.open(Number(data.inventoryArtifact)), "artifact-details");
  } else if (data.query) {
    show("query", {enter:false});
    $("query_q").value = data.query;
    S.query.reset();
    S.query.loadSaved();
  } else if (data.deleteQuery) {
    act(target, () => S.library.remove(data.deleteQuery), "o_library");
  }
});
document.addEventListener("change", event => {
  if (["message-side", "message-view"].includes(event.target.id)) showMessage();
  if (event.target.id === "workflow-select") S.workflows.select(v("workflow-select"));
  if (event.target.id === "workflow-version") S.workflows.select(v("workflow-select"), v("workflow-version"));
  if (event.target.id === "workflow-archive") S.workflows.sync();
  if (event.target.matches("[data-review-check]")) S.workflows.changeChecks();
  if (event.target.id === "reduce-motion") {
    const preference = event.target.checked ? "reduced" : "system";
    document.documentElement.dataset.motion = preference;
    try { localStorage.setItem("camio-motion", preference); } catch (_) { /* Session preference still applies. */ }
  }
});
document.addEventListener("input", event => {
  if (event.target.id === "workflow-json") {
    S.workflows.jsonDirty = true;
    S.workflows.sync();
  }
  if (["workflow-name", "workflow-query", "workflow-limit", "workflow-save"].includes(event.target.id)) {
    S.workflows.sync();
  }
});
document.addEventListener("keydown", event => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    openSearch();
  } else if (event.key === "Enter" && event.target.id === "tool-search") {
    $("tool-results").querySelector("button")?.click();
  } else if (event.key === "Enter" && ["history_q", "query_q"].includes(event.target.id)) {
    S[current].reset();
  } else if (event.key === "Enter" && event.target.id === "asset-filter") {
    $("asset-search").click();
  }
});
$("command-trigger").addEventListener("click", openSearch);
$("tool-search").addEventListener("input", searchTools);
$("nav-toggle").addEventListener("click", () => {
  const opened = $("rail").classList.toggle("is-open");
  $("nav-toggle").setAttribute("aria-expanded", String(opened));
});
$("inspector").addEventListener("close", () => { inspector = null; out("inspector-content", ""); });
window.addEventListener("popstate", () => {
  const id = location.hash.slice(1);
  if (Object.hasOwn(S, id)) show(id, {push:false});
  else if (!id) show("status", {push:false});
});
window.setInterval(() => {
  if (!document.hidden && current === "tasks" && S.tasks.active) S.tasks.enter();
}, 1200);

async function boot() {
  const match = /^#session=([a-f0-9]{64})$/.exec(location.hash);
  if (match) {
    sessionKey = match[1];
    history.replaceState(null, "", location.pathname + "#status");
  }
  try {
    if (sessionKey) sessionStorage.setItem("camio-session", sessionKey);
    else sessionKey = sessionStorage.getItem("camio-session") || "";
    document.documentElement.dataset.motion = localStorage.getItem("camio-motion") || "system";
  } catch (_) { /* The pasted launch URL works without Web Storage. */ }
  out("nav", NAV.map(([group, items]) => '<div class="group-label">' + group + "</div>"
    + items.map(([id, label, icon]) => '<button type="button" data-go="' + id + '"><span class="nav-icon" aria-hidden="true">'
      + esc(icon) + "</span>" + esc(label) + "</button>").join("")).join(""));
  const examples = document.createElement("datalist");
  examples.id = "query-examples";
  examples.innerHTML = ['resp.code.gte:400','req.method.eq:GET','req.host.cont:"example"','resp.len.gt:1024','source.eq:import'].map(value => '<option value="' + esc(value) + '"></option>').join("");
  document.body.appendChild(examples);
  const initial = location.hash.slice(1);
  show(Object.hasOwn(S, initial) ? initial : "status", { push:false, focus:false, enter:false });
  if (!sessionKey) {
    connection("offline", "Open the full session link printed by Camio to connect to this workspace.");
    out("overview-transport", "<dt>Status</dt><dd>Waiting for a local session.</dd>");
    return;
  }
  try {
    meta = await api("meta");
    if (S[current].enter) await S[current].enter();
    if ($("tx_hint")) output("tx_hint", "Available steps: " + meta.transforms.join(", "));
  } catch (error) {
    if ($("overview-transport")) out("overview-transport", "<dt>Status</dt><dd>" + esc(error.message) + "</dd>");
  }
}
boot();

use super::{open, WebConfig};
use anyhow::{anyhow, ensure, Context, Result};
use camio_core::{ExchangeId, FindingId, Query, TaskId};
use camio_store::{ArtifactFormat, ReportFormat, ReviewPlan, ReviewState};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Page {
    limit: Option<usize>,
    before: Option<ExchangeId>,
    query: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    id: ExchangeId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingPage {
    state: Option<ReviewState>,
    #[serde(default)]
    offset: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    id: FindingId,
    state: ReviewState,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveQuery {
    name: String,
    expression: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Name {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bookmark {
    id: ExchangeId,
    #[serde(default)]
    label: String,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartReview {
    #[serde(default)]
    query: String,
    limit: Option<usize>,
    #[serde(default)]
    save: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskPage {
    id: TaskId,
    #[serde(default)]
    offset: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportArtifact {
    format: ArtifactFormat,
    content: String,
    version: Option<String>,
    #[serde(default)]
    save: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    id: i64,
    before: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    before: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Offset {
    #[serde(default)]
    offset: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    format: ReportFormat,
    state: Option<ReviewState>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workflow {
    id: i64,
    version: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartWorkflow {
    id: i64,
    version: i64,
    archive: Option<ArchiveInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveInput {
    name: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskReport {
    id: TaskId,
    format: ReportFormat,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryPage {
    #[serde(default)]
    filter: String,
    after: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetPage {
    origin: String,
    after: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryLocation {
    location: String,
    before: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryNote {
    origin: String,
    label: String,
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveWorkflow {
    name: String,
    plan: ReviewPlan,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Compare {
    a: String,
    b: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JavaScript {
    code: String,
}

pub(super) fn dispatch(cfg: &WebConfig, path: &str, args: &Value) -> Option<Result<Value, String>> {
    let store = || open(cfg).map_err(|message| anyhow!(message));
    let result: Result<Value> = (|| {
        Ok(match path {
            "/api/workspace" => {
                let store = store()?;
                let query = Query::compile("")?;
                let recent = store.history_page(&query, None, 6)?;
                json!({
                    "workspace": store.workspace()?,
                    "exchanges": recent.exchanges,
                    "tasks": store.review_tasks()?.into_iter().take(3).collect::<Vec<_>>(),
                })
            }
            "/api/workspace/rename" => {
                store()?.rename_workspace(&Name::deserialize(args)?.name)?;
                json!({ "saved": true })
            }
            "/api/history" | "/api/query" => {
                let args = Page::deserialize(args)?;
                let query = compile(if path == "/api/query" {
                    &args.query
                } else {
                    ""
                })?;
                let page = store()?.history_page(&query, args.before, args.limit.unwrap_or(100))?;
                json!({ "count": page.exchanges.len(), "exchanges": page.exchanges,
                        "next_before": page.next_before, "skipped_large": page.skipped_large })
            }
            "/api/exchange" => {
                let id = Exchange::deserialize(args)?.id;
                let store = store()?;
                let preview = store
                    .inspect_exchange(id)?
                    .context("exchange was not found")?;
                json!({ "preview": preview, "saved": store.saved_exchange(id)? })
            }
            "/api/queries" => json!({ "queries": store()?.saved_queries()? }),
            "/api/queries/save" => {
                let args = SaveQuery::deserialize(args)?;
                store()?.save_query(&args.name, &args.expression)?;
                json!({ "saved": true })
            }
            "/api/queries/delete" => {
                store()?.delete_query(&Name::deserialize(args)?.name)?;
                json!({ "deleted": true })
            }
            "/api/library" => {
                let offset = bounded_offset(Offset::deserialize(args)?.offset)?;
                let store = store()?;
                let exchanges = store.saved_exchanges(offset)?;
                json!({ "queries": store.saved_queries()?, "exchanges": exchanges,
                        "next_offset": (exchanges.len() == 100).then_some(offset + 100) })
            }
            "/api/library/save" => {
                let args = Bookmark::deserialize(args)?;
                store()?.save_exchange(args.id, &args.label, &args.note)?;
                json!({ "saved": true })
            }
            "/api/library/delete" => {
                store()?.delete_saved_exchange(Exchange::deserialize(args)?.id)?;
                json!({ "deleted": true })
            }
            "/api/findings" => {
                let args = FindingPage::deserialize(args)?;
                let offset = bounded_offset(args.offset)?;
                let findings = store()?.finding_reviews(args.state, offset, 50)?;
                json!({ "count": findings.len(), "findings": findings,
                        "next_offset": (findings.len() == 50).then_some(offset + 50) })
            }
            "/api/findings/review" => {
                let args = Review::deserialize(args)?;
                store()?.update_finding_review(args.id, args.state, &args.note)?;
                json!({ "saved": true })
            }
            "/api/findings/report" => {
                let args = Report::deserialize(args)?;
                let report = store()?.finding_report(args.state)?;
                json!({ "filename": args.format.filename(), "content": report.render(args.format)? })
            }
            "/api/workflows" => json!({ "workflows": store()?.review_workflows()? }),
            "/api/workflows/save" => {
                let args = SaveWorkflow::deserialize(args)?;
                camio_scan::validate_review_plan(&args.plan)?;
                let mut store = store()?;
                let workflow = store.save_review_workflow(&args.name, &args.plan)?;
                json!({ "versions": store.review_workflow_versions(workflow.revision.id)?, "workflow": workflow })
            }
            "/api/workflows/get" => {
                let args = Workflow::deserialize(args)?;
                let store = store()?;
                let workflow = store
                    .review_workflow(args.id, args.version)?
                    .context("workflow version was not found")?;
                json!({ "workflow": workflow, "versions": store.review_workflow_versions(args.id)? })
            }
            "/api/workflows/start" => {
                let args = StartWorkflow::deserialize(args)?;
                let version = Some(args.version);
                let id = match args.archive {
                    Some(archive) => camio_scan::start_archive_review(
                        &cfg.db,
                        args.id,
                        version,
                        camio_scan::ReviewArchiveInput::Bytes {
                            name: archive.name,
                            data: archive.content.into_bytes(),
                        },
                    )?,
                    None => camio_scan::start_review_workflow(&cfg.db, args.id, version)?,
                };
                json!({ "id": id })
            }
            "/api/review/start" => {
                let args = StartReview::deserialize(args)?;
                let id = camio_scan::start_passive_review(
                    &cfg.db,
                    &args.query,
                    args.limit.unwrap_or(200),
                    args.save,
                )?;
                json!({ "id": id })
            }
            "/api/review/tasks" => json!({ "tasks": store()?.review_tasks()? }),
            "/api/review/checks" => json!({ "checks": camio_scan::review_checks() }),
            "/api/review/task" => {
                let args = TaskPage::deserialize(args)?;
                let offset = bounded_offset(args.offset)?;
                let store = store()?;
                let task = store
                    .review_task(args.id)?
                    .context("review task was not found")?;
                let findings = store.review_results(args.id, offset)?;
                json!({ "task": task, "findings": findings,
                        "next_offset": (findings.len() == 50).then_some(offset + 50) })
            }
            "/api/review/cancel" => {
                let args = TaskPage::deserialize(args)?;
                json!({ "cancelled": store()?.cancel_review(args.id)? })
            }
            "/api/review/report" => {
                let args = TaskReport::deserialize(args)?;
                let report = store()?.review_report(args.id)?;
                json!({ "filename": args.format.review_filename(args.id), "content": report.render(args.format)? })
            }
            "/api/review/bundle" => {
                let id = TaskPage::deserialize(args)?.id;
                let bundle = store()?.review_evidence_bundle(id)?;
                json!({ "filename": format!("camio-review-{id}-evidence.json"), "content": serde_json::to_string_pretty(&bundle)? })
            }
            "/api/inventory" => {
                let args = InventoryPage::deserialize(args)?;
                serde_json::to_value(store()?.inventory(&args.filter, args.after.as_deref())?)?
            }
            "/api/inventory/asset" => {
                let args = AssetPage::deserialize(args)?;
                serde_json::to_value(
                    store()?.asset_inventory(&args.origin, args.after.as_deref())?,
                )?
            }
            "/api/inventory/evidence" => {
                let args = InventoryLocation::deserialize(args)?;
                serde_json::to_value(store()?.endpoint_evidence(&args.location, args.before)?)?
            }
            "/api/inventory/note" => {
                let args = InventoryNote::deserialize(args)?;
                store()?.save_asset_note(&args.origin, &args.label, &args.note)?;
                json!({ "saved": true })
            }
            "/api/artifacts/import" => {
                let args = ImportArtifact::deserialize(args)?;
                serde_json::to_value(store()?.import_artifact(
                    args.format,
                    &args.content,
                    args.version.as_deref(),
                    args.save,
                )?)?
            }
            "/api/artifacts" => {
                let records = store()?.artifacts(Cursor::deserialize(args)?.before)?;
                json!({ "artifacts": records, "next_before": (records.len() == 50).then(|| records[49].id) })
            }
            "/api/artifacts/observations" => {
                let args = Artifact::deserialize(args)?;
                serde_json::to_value(store()?.observations(args.id, args.before)?)?
            }
            "/api/artifacts/raw" => {
                let id = Artifact::deserialize(args)?.id;
                let content = store()?
                    .artifact_text(id)?
                    .context("artifact was not found")?;
                json!({ "content": content })
            }
            "/api/compare" => {
                let args = Compare::deserialize(args)?;
                ensure!(
                    args.a.len() + args.b.len() <= 128 * 1024,
                    "compare up to 128 KiB of text"
                );
                ensure!(
                    (args.a.lines().count() + 1).saturating_mul(args.b.lines().count() + 1)
                        <= 2_000_000,
                    "compare fewer lines at a time"
                );
                let diff = camio_convert::diff_bytes(args.a.as_bytes(), args.b.as_bytes());
                let lines = camio_convert::unified_diff(&args.a, &args.b, 3);
                json!({ "bytes": diff, "lines": lines })
            }
            "/api/analyze-js" => {
                let args = JavaScript::deserialize(args)?;
                ensure!(
                    args.code.len() <= 2 * 1024 * 1024,
                    "inspect up to 2 MiB of source"
                );
                serde_json::to_value(camio_scan::analyze_js(&args.code))?
            }
            _ => return Ok(Value::Null),
        })
    })();
    match result {
        Ok(Value::Null) => None,
        other => Some(other.map_err(|error| format!("{error:#}"))),
    }
}

pub(super) fn compile(query: &str) -> Result<Query> {
    ensure!(query.len() <= 1024, "CamioQL filters support 1024 bytes");
    Query::compile(query).context("invalid CamioQL")
}

fn bounded_offset(offset: usize) -> Result<usize> {
    ensure!(offset <= 1_000_000, "offset exceeds the supported range");
    Ok(offset)
}

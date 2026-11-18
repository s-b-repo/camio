use anyhow::{bail, ensure, Context, Result};
use camio_core::{ExchangeId, FindingId, Query, TaskId, TaskState};
use camio_store::{
    ArtifactFormat, ReviewEvidenceBundle, ReviewPlan, ReviewState, Store, ARTIFACT_BYTES,
    MAX_BUNDLE_BYTES,
};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
pub(super) struct Args {
    /// SQLite store for this workspace.
    #[arg(long, global = true, default_value = "camio.db")]
    db: PathBuf,
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Print workspace totals and saved project name.
    Summary,
    /// Set the saved name for this database.
    Rename { name: String },
    /// Write a consistent copy of the workspace to a new SQLite file.
    Backup { file: PathBuf },
    /// Page through stored history without loading message bodies.
    History {
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long)]
        before: Option<i64>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show ordered headers and the first 64 KiB of each stored body.
    Inspect { id: i64 },
    /// Import or preview a previously exported integration report.
    ImportEvidence {
        #[arg(value_enum)]
        format: InputFormat,
        file: PathBuf,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        preview: bool,
    },
    /// List stored integration evidence.
    Artifacts {
        #[arg(long)]
        before: Option<i64>,
    },
    /// List normalized observations in a stored artifact.
    Observations {
        id: i64,
        #[arg(long)]
        before: Option<i64>,
    },
    /// List assets recorded in local traffic and imported observations.
    Inventory {
        #[arg(long, default_value = "")]
        filter: String,
        #[arg(long)]
        after: Option<String>,
    },
    /// Show an asset's notes and endpoint observations.
    Asset {
        origin: String,
        #[arg(long)]
        after: Option<String>,
    },
    /// List source records associated with a recorded endpoint.
    EndpointEvidence {
        location: String,
        #[arg(long)]
        before: Option<i64>,
    },
    /// Review stored exchanges in the background and wait for the final state.
    Review {
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        save: bool,
    },
    /// List recent passive review tasks.
    Tasks,
    /// List available passive check identifiers for saved workflows.
    ReviewChecks,
    /// Save, inspect, or run a versioned review plan for stored exchanges.
    Workflow {
        #[command(subcommand)]
        command: WorkflowCommand,
    },
    /// Print review progress and a page of results.
    Task {
        id: i64,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Cancel a queued or running passive review.
    Cancel { id: i64 },
    /// Export results and provenance for one finished review task.
    ReviewReport {
        id: i64,
        #[arg(long, value_enum, default_value = "markdown")]
        format: ReportFormat,
    },
    /// Export a finished review report and redacted evidence with checksums.
    ReviewBundle { id: i64 },
    /// Update a finding's status and review notes.
    Triage {
        id: i64,
        #[arg(value_enum)]
        status: Status,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Export a redacted finding summary to standard output.
    Report {
        #[arg(long, value_enum, default_value = "markdown")]
        format: ReportFormat,
        #[arg(long, value_enum)]
        status: Option<Status>,
    },
}

#[derive(Subcommand)]
enum WorkflowCommand {
    /// List the latest version of each saved workflow.
    List,
    /// Save a JSON review plan as a version under the given name.
    Save { name: String, file: PathBuf },
    /// Print the JSON document for a saved workflow version.
    Show {
        id: i64,
        #[arg(long)]
        version: Option<i64>,
    },
    /// Run a saved workflow version on existing traffic and wait for its results.
    Run {
        id: i64,
        #[arg(long)]
        version: Option<i64>,
        /// Import this HAR or Burp items archive and review its exchanges.
        #[arg(long)]
        archive: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum InputFormat {
    Httpx,
    Nuclei,
    Raw,
}

impl From<InputFormat> for ArtifactFormat {
    fn from(format: InputFormat) -> Self {
        match format {
            InputFormat::Httpx => Self::Httpx,
            InputFormat::Nuclei => Self::Nuclei,
            InputFormat::Raw => Self::Raw,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Status {
    Open,
    Confirmed,
    Resolved,
    Dismissed,
}

impl From<Status> for ReviewState {
    fn from(status: Status) -> Self {
        match status {
            Status::Open => Self::Open,
            Status::Confirmed => Self::Confirmed,
            Status::Resolved => Self::Resolved,
            Status::Dismissed => Self::Dismissed,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ReportFormat {
    Markdown,
    Json,
    Html,
    Sarif,
}

impl From<ReportFormat> for camio_store::ReportFormat {
    fn from(format: ReportFormat) -> Self {
        match format {
            ReportFormat::Markdown => Self::Markdown,
            ReportFormat::Json => Self::Json,
            ReportFormat::Html => Self::Html,
            ReportFormat::Sarif => Self::Sarif,
        }
    }
}

pub(super) fn run(args: Args) -> Result<()> {
    let mut store = Store::open(&args.db)?;
    let output = match args.operation {
        Operation::Summary => json!(store.workspace()?),
        Operation::Rename { name } => {
            store.rename_workspace(&name)?;
            json!(store.workspace()?)
        }
        Operation::Backup { file } => {
            store.backup_to(&file)?;
            json!({ "backup": file })
        }
        Operation::History {
            query,
            before,
            limit,
        } => {
            ensure!(
                query.len() <= 1024,
                "CamioQL filters support up to 1024 bytes"
            );
            ensure!((1..=200).contains(&limit), "use a page size from 1 to 200");
            json!(store.history_page(&Query::compile(&query)?, before.map(ExchangeId), limit)?)
        }
        Operation::Inspect { id } => json!(store
            .inspect_exchange(ExchangeId(id))?
            .context("exchange was not found")?),
        Operation::ImportEvidence {
            format,
            file,
            version,
            preview,
        } => {
            ensure!(file.metadata()?.is_file(), "select a regular file");
            let mut content = String::new();
            std::fs::File::open(&file)?
                .take(ARTIFACT_BYTES as u64 + 1)
                .read_to_string(&mut content)?;
            json!(store.import_artifact(format.into(), &content, version.as_deref(), !preview)?)
        }
        Operation::Artifacts { before } => json!(store.artifacts(before)?),
        Operation::Observations { id, before } => json!(store.observations(id, before)?),
        Operation::Inventory { filter, after } => {
            json!(store.inventory(&filter, after.as_deref())?)
        }
        Operation::Asset { origin, after } => {
            json!(store.asset_inventory(&origin, after.as_deref())?)
        }
        Operation::EndpointEvidence { location, before } => {
            json!(store.endpoint_evidence(&location, before)?)
        }
        Operation::Review { query, limit, save } => {
            let id = camio_scan::start_passive_review(&args.db, &query, limit, save)?;
            return wait_for_review(&store, id);
        }
        Operation::Tasks => json!(store.review_tasks()?),
        Operation::ReviewChecks => json!(camio_scan::review_checks()),
        Operation::Workflow { command } => match command {
            WorkflowCommand::List => json!(store.review_workflows()?),
            WorkflowCommand::Save { name, file } => {
                let metadata = file.metadata()?;
                ensure!(
                    metadata.is_file() && metadata.len() <= 8192,
                    "select a JSON plan file of up to 8 KiB"
                );
                let mut contents = Vec::new();
                std::fs::File::open(file)?
                    .take(8193)
                    .read_to_end(&mut contents)?;
                ensure!(
                    contents.len() <= 8192,
                    "select a JSON plan file of up to 8 KiB"
                );
                let plan: ReviewPlan =
                    serde_json::from_slice(&contents).context("invalid review plan document")?;
                camio_scan::validate_review_plan(&plan)?;
                json!(store.save_review_workflow(&name, &plan)?)
            }
            WorkflowCommand::Show { id, version } => json!(
                store
                    .review_workflow(id, version)?
                    .context("workflow version was not found")?
                    .plan
            ),
            WorkflowCommand::Run {
                id,
                version,
                archive,
            } => {
                let task = match archive {
                    Some(path) => camio_scan::start_archive_review(
                        &args.db,
                        id,
                        version,
                        camio_scan::ReviewArchiveInput::File(path),
                    )?,
                    None => camio_scan::start_review_workflow(&args.db, id, version)?,
                };
                return wait_for_review(&store, task);
            }
        },
        Operation::Task { id, offset } => {
            let id = TaskId(id);
            let task = store
                .review_task(id)?
                .context("review task was not found")?;
            json!({ "task": task, "findings": store.review_results(id, offset)? })
        }
        Operation::Cancel { id } => json!({ "cancelled": store.cancel_review(TaskId(id))? }),
        Operation::ReviewReport { id, format } => {
            return print_report(&store.review_report(TaskId(id))?, format);
        }
        Operation::ReviewBundle { id } => json!(store.review_evidence_bundle(TaskId(id))?),
        Operation::Triage { id, status, note } => {
            store.update_finding_review(FindingId(id), status.into(), &note)?;
            json!(store.finding_review(FindingId(id))?)
        }
        Operation::Report { format, status } => {
            let report = store.finding_report(status.map(Into::into))?;
            return print_report(&report, format);
        }
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

pub(super) fn verify_bundle(file: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_BUNDLE_BYTES,
        "select an evidence bundle of up to 16 MiB"
    );
    let mut data = Vec::new();
    std::fs::File::open(file)?
        .take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut data)?;
    let bundle = ReviewEvidenceBundle::verified_json(&data)?;
    println!(
        "{}",
        json!({"valid": true, "exchanges": bundle.evidence.len(), "unavailable": bundle.manifest.unavailable.len()})
    );
    Ok(())
}

fn print_report(report: &camio_store::FindingReport, format: ReportFormat) -> Result<()> {
    let content = report.render(format.into())?;
    if content.ends_with('\n') {
        print!("{content}");
    } else {
        println!("{content}");
    }
    Ok(())
}

fn wait_for_review(store: &Store, id: TaskId) -> Result<()> {
    eprintln!("Passive review #{id} queued.");
    loop {
        let task = store
            .review_task(id)?
            .context("review task was not found")?;
        if !matches!(task.task.state, TaskState::Pending | TaskState::Running) {
            println!("{}", serde_json::to_string_pretty(&task)?);
            if matches!(task.task.state, TaskState::Failed | TaskState::Interrupted) {
                bail!(
                    "{}",
                    task.error.as_deref().unwrap_or("review did not complete")
                );
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

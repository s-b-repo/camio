use super::default_checks;
use anyhow::{ensure, Context, Result};
use camio_core::{ExchangeId, Query, TaskId};
use camio_store::{
    ReviewCandidate, ReviewCounts, ReviewPlan, Store, ARTIFACT_BYTES, REVIEW_BODY_LIMIT,
};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;

const BATCH: usize = 12;
const MAX_CANDIDATES_PER_EXCHANGE: usize = 80;

/// A capture selected by the operator. URL fields inside it are treated as data.
pub enum ReviewArchiveInput {
    File(PathBuf),
    Bytes { name: String, data: Vec<u8> },
}

impl ReviewArchiveInput {
    fn name(&self) -> Result<String> {
        match self {
            Self::File(path) => Ok(path
                .file_name()
                .context("select a capture archive")?
                .to_string_lossy()
                .into_owned()),
            Self::Bytes { name, data } => {
                validate_archive_size(data.len())?;
                Ok(name.clone())
            }
        }
    }

    fn read(self) -> Result<Vec<u8>> {
        match self {
            Self::Bytes { data, .. } => Ok(data),
            Self::File(path) => {
                let metadata = path.metadata().context("reading capture file metadata")?;
                ensure!(metadata.is_file(), "select a regular capture file");
                ensure!(
                    metadata.len() <= ARTIFACT_BYTES as u64,
                    "capture archives support up to 4 MiB"
                );
                let mut data = Vec::new();
                std::fs::File::open(path)
                    .context("opening the capture archive")?
                    .take(ARTIFACT_BYTES as u64 + 1)
                    .read_to_end(&mut data)
                    .context("reading the capture archive")?;
                validate_archive_size(data.len())?;
                Ok(data)
            }
        }
    }
}

fn validate_archive_size(bytes: usize) -> Result<()> {
    ensure!(bytes > 0, "the capture archive is empty");
    ensure!(
        bytes <= ARTIFACT_BYTES,
        "capture archives support up to 4 MiB"
    );
    Ok(())
}

/// Queue a read-only review of a fixed snapshot of stored exchanges. The
/// worker has no request engine or framework access.
pub fn start_passive_review(db: &Path, filter: &str, limit: usize, save: bool) -> Result<TaskId> {
    let query = ReviewPlan::new(filter, limit, save).compile()?;
    let store = Store::open(db)?;
    let id = store.queue_review(query.source(), limit, save)?;
    launch(db, store, id, query, None)
}

pub fn start_review_workflow(db: &Path, workflow: i64, version: Option<i64>) -> Result<TaskId> {
    let store = Store::open(db)?;
    let (id, query) = store.queue_saved_review(workflow, version)?;
    launch(db, store, id, query, None)
}

/// Import a HAR or Burp items archive, then review its recorded exchanges.
pub fn start_archive_review(
    db: &Path,
    workflow: i64,
    version: Option<i64>,
    archive: ReviewArchiveInput,
) -> Result<TaskId> {
    let store = Store::open(db)?;
    let (id, query) = store.queue_archive_review(workflow, version, &archive.name()?)?;
    launch(db, store, id, query, Some(archive))
}

fn launch(
    db: &Path,
    store: Store,
    id: TaskId,
    query: Query,
    archive: Option<ReviewArchiveInput>,
) -> Result<TaskId> {
    if let Err(error) = thread::Builder::new()
        .name(format!("camio-review-{id}"))
        .spawn(move || {
            let mut store = store;
            if let Err(error) = run(&mut store, id, &query, archive) {
                if let Err(record_error) = store.fail_review(id, &format!("{error:#}")) {
                    eprintln!("could not record passive review {id} failure: {record_error}");
                }
            }
        })
    {
        Store::open(db)?.fail_review(id, "could not start the review worker")?;
        return Err(error.into());
    }
    Ok(id)
}

fn run(
    store: &mut Store,
    id: TaskId,
    query: &Query,
    archive: Option<ReviewArchiveInput>,
) -> Result<()> {
    if !store.start_review(id)? {
        return Ok(());
    }
    if let Some(input) = archive {
        let data = input.read()?;
        let capture = camio_import::import_bytes(&data).context("importing the capture archive")?;
        if !store.commit_review_archive(
            id,
            &data,
            capture.format,
            &capture.exchanges,
            &capture.warnings,
        )? {
            return Ok(());
        }
    }
    let job = store.review_task(id)?.context("review task disappeared")?;
    let Some(snapshot) = job.snapshot else {
        store.finish_review(id)?;
        return Ok(());
    };
    let first = job
        .archive
        .as_ref()
        .map(|archive| {
            archive
                .first_exchange
                .context("archive exchange bounds were not recorded")
        })
        .transpose()?;
    let checks = default_checks();
    let all = Query::compile("")?;
    let mut before = snapshot.0.checked_add(1).map(ExchangeId);
    let mut counts = ReviewCounts::default();
    loop {
        let history = store.history_page(&all, before, BATCH.min(job.limit - counts.examined))?;
        let mut candidates = Vec::new();
        let mut reached_start = false;
        for row in history.exchanges {
            if first.is_some_and(|first| row.id < first) {
                reached_start = true;
                break;
            }
            reached_start = first == Some(row.id);
            counts.examined += 1;
            if row.req_len > REVIEW_BODY_LIMIT || row.resp_len.unwrap_or(0) > REVIEW_BODY_LIMIT {
                counts.skipped_large += 1;
                continue;
            }
            let exchange = store.get(row.id)?.context("stored exchange disappeared")?;
            if !query.matches(&exchange) {
                continue;
            }
            counts.scanned += 1;
            let host = row.host.unwrap_or_default();
            let mut accepted = 0;
            for check in &checks {
                for finding in check.check(&exchange) {
                    if accepted == MAX_CANDIDATES_PER_EXCHANGE {
                        counts.omitted += 1;
                        continue;
                    }
                    accepted += 1;
                    candidates.push(ReviewCandidate {
                        rule: check.id(),
                        host: host.clone(),
                        finding,
                    });
                }
            }
        }
        if !store.commit_review(id, &counts, &candidates, job.save)? {
            return Ok(());
        }
        before = history.next_before;
        if counts.examined == job.limit || before.is_none() || reached_start {
            store.finish_review(id)?;
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{
        Body, HeaderList, HttpExchange, HttpRequest, HttpResponse, HttpVersion, Source,
    };
    use camio_store::{ReportFormat, ReviewState};

    #[test]
    fn reviews_real_body_bytes_and_preserves_triage_across_runs() {
        let mut store = Store::open_in_memory().unwrap();
        let exchange = HttpExchange::new(
            HttpRequest::get("https://fixture.test/files"),
            Source::Import,
        )
        .with_response(HttpResponse {
            status: 200,
            reason: None,
            version: HttpVersion::Http11,
            headers: HeaderList::new(),
            body: Body::from_text("<html><title>Index of /files</title></html>"),
        });
        let evidence = store.insert(&exchange).unwrap();
        let first = store.queue_review("resp.code:200", 10, true).unwrap();
        let filter = Query::compile("resp.code:200").unwrap();
        // New traffic after task creation is left for the next review.
        let second_evidence = store.insert(&exchange).unwrap();
        run(&mut store, first, &filter, None).unwrap();
        let task = store.review_task(first).unwrap().unwrap();
        assert_eq!(task.counts.scanned, 1);
        let saved = store.finding_reviews(None, 0, 20).unwrap();
        let listing = saved
            .iter()
            .find(|finding| finding.rule.as_deref() == Some("directory-listing"))
            .unwrap();
        assert_eq!(listing.finding.evidence, vec![evidence]);
        let finding = listing.finding.id;
        store
            .update_finding_review(finding, ReviewState::Confirmed, "Reviewed in fixture")
            .unwrap();
        let next = store.queue_review("resp.code:200", 10, true).unwrap();
        run(&mut store, next, &filter, None).unwrap();
        let listing = store.finding_review(finding).unwrap().unwrap();
        assert_eq!(listing.state, ReviewState::Confirmed);
        assert_eq!(listing.finding.evidence, vec![evidence, second_evidence]);
    }

    #[test]
    fn archive_runs_isolate_and_reuse_the_capture_and_export_only_run_evidence() {
        let mut store = Store::open_in_memory().unwrap();
        let old = store
            .insert(&HttpExchange::new(
                HttpRequest::get("https://older.test/history"),
                Source::Import,
            ))
            .unwrap();
        let workflow = store
            .save_review_workflow("Internal review marker", &ReviewPlan::new("", 10, false))
            .unwrap();
        let id = workflow.revision.id;
        let capture = br#"{"log":{"entries":[{}, {"request":{"url":"https://archive.test/files"},"response":{"status":200,"content":{"text":"<title>Index of /files</title>"}}}]}}"#;
        let input = |name: &str| ReviewArchiveInput::Bytes {
            name: name.into(),
            data: capture.to_vec(),
        };

        let (task, query) = store
            .queue_archive_review(id, Some(1), "private-capture.har")
            .unwrap();
        assert!(store.review_report(task).is_err());
        run(&mut store, task, &query, Some(input("private-capture.har"))).unwrap();
        let completed = store.review_task(task).unwrap().unwrap();
        let added = completed.snapshot.unwrap();
        assert!(added > old);
        assert_eq!(completed.counts.examined, 1);
        assert_eq!(completed.counts.scanned, 1);
        let capture_info = completed.archive.unwrap();
        assert_eq!(capture_info.imported, Some(1));
        assert_eq!(capture_info.warning_count, 1);
        assert!(!capture_info.reused);
        let checksum = capture_info.sha256.unwrap();

        let report = store.review_report(task).unwrap();
        assert!(!report.findings.is_empty());
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.evidence == vec![added]));
        for format in ReportFormat::ALL {
            let rendered = report.render(format).unwrap();
            assert!(rendered.contains(&checksum));
            assert!(rendered.contains("directory-listing"));
            assert!(!rendered.contains("private-capture.har"));
            assert!(!rendered.contains("archive.test"));
            assert!(!rendered.contains("Internal review marker"));
        }
        let bundle = store.review_evidence_bundle(task).unwrap();
        assert_eq!(bundle.evidence.len(), 1);
        let mut exported = serde_json::to_value(bundle).unwrap();
        let original = serde_json::to_vec_pretty(&exported).unwrap();
        assert!(camio_store::ReviewEvidenceBundle::verified_json(&original).is_ok());
        assert!(!String::from_utf8(original).unwrap().contains("archive.test"));
        exported["evidence"][0]["status"] = serde_json::json!(404);
        assert!(camio_store::ReviewEvidenceBundle::verified_json(&serde_json::to_vec(&exported).unwrap()).is_err());

        store
            .insert(&HttpExchange::new(
                HttpRequest::get("https://later.test/history"),
                Source::Import,
            ))
            .unwrap();
        let (retry, query) = store
            .queue_archive_review(id, Some(1), "renamed.har")
            .unwrap();
        run(&mut store, retry, &query, Some(input("renamed.har"))).unwrap();
        let completed = store.review_task(retry).unwrap().unwrap();
        assert_eq!(completed.snapshot, Some(added));
        assert_eq!(completed.counts.examined, 1);
        assert!(completed.archive.unwrap().reused);
        assert_eq!(store.count().unwrap(), 3);

        let (empty, query) = store
            .queue_archive_review(id, Some(1), "empty.har")
            .unwrap();
        let empty_input = ReviewArchiveInput::Bytes {
            name: "empty.har".into(),
            data: br#"{"log":{"entries":[]}}"#.to_vec(),
        };
        run(&mut store, empty, &query, Some(empty_input)).unwrap();
        let empty = store.review_task(empty).unwrap().unwrap();
        assert_eq!(empty.counts.examined, 0);
        assert_eq!(empty.archive.unwrap().imported, Some(0));
    }
}

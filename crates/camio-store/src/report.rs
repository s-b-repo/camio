use super::{ReviewCounts, ReviewState, Store};
use anyhow::{ensure, Context, Result};
use camio_core::{Confidence, ExchangeId, Finding, FindingId, Severity, TaskId, TaskState};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Markdown,
    Json,
    Html,
    Sarif,
}

impl ReportFormat {
    pub const ALL: [Self; 4] = [Self::Markdown, Self::Json, Self::Html, Self::Sarif];

    pub fn label(self) -> &'static str {
        match self {
            Self::Markdown => "Markdown",
            Self::Json => "JSON",
            Self::Html => "HTML",
            Self::Sarif => "SARIF",
        }
    }

    pub fn filename(self) -> &'static str {
        match self {
            Self::Markdown => "camio-findings.md",
            Self::Json => "camio-findings.json",
            Self::Html => "camio-findings.html",
            Self::Sarif => "camio-findings.sarif",
        }
    }

    pub fn review_filename(self, task: TaskId) -> String {
        // A format without an extension is a programming error, not something a
        // caller can cause — and the answer is a filename with no extension,
        // not a panic while naming a file to hand to the operator.
        let extension = self.filename().rsplit_once('.').map_or("", |(_, ext)| ext);
        if extension.is_empty() {
            return format!("camio-review-{task}");
        }
        format!("camio-review-{task}.{extension}")
    }
}

/// Shareable summary with a field allowlist. Free text and raw evidence stay in
/// the workspace because they may contain credentials or customer data.
#[derive(Debug, Deserialize, Serialize)]
pub struct FindingReport {
    pub schema_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<ReportRun>,
    pub findings: Vec<ReportEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReportEntry {
    pub id: Option<FindingId>,
    pub rule: Option<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub state: Option<ReviewState>,
    pub evidence: Vec<ExchangeId>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReportRun {
    pub id: TaskId,
    pub state: TaskState,
    pub limit: usize,
    pub counts: ReviewCounts,
    pub workflow_id: Option<i64>,
    pub workflow_version: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_ids: Option<Vec<String>>,
    pub archive: Option<ReportArchive>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReportArchive {
    pub format: Option<String>,
    pub sha256: Option<String>,
    pub imported: Option<usize>,
    pub warning_count: usize,
    pub reused: bool,
}

impl Store {
    /// Export results attached to a finished task. Captured URLs, archive
    /// names, filter text, and diagnostics are omitted from shareable exports.
    pub fn review_report(&self, id: TaskId) -> Result<FindingReport> {
        let task = self.review_task(id)?.context("review task was not found")?;
        ensure!(
            !matches!(task.task.state, TaskState::Pending | TaskState::Running),
            "wait for the review to finish before exporting its report"
        );
        let check_ids = if let Some(version) = task.workflow.as_ref() {
            self.review_workflow(version.id, Some(version.version))?
                .context("review workflow version disappeared")?
                .plan
                .check_ids
        } else {
            None
        };
        let run = ReportRun {
            id,
            state: task.task.state,
            limit: task.limit,
            counts: task.counts,
            workflow_id: task.workflow.as_ref().map(|version| version.id),
            workflow_version: task.workflow.map(|version| version.version),
            check_ids,
            archive: task.archive.map(|archive| ReportArchive {
                format: archive.format,
                sha256: archive.sha256,
                imported: archive.imported,
                warning_count: archive.warning_count,
                reused: archive.reused,
            }),
        };
        let mut stmt = self.conn.prepare(
            "SELECT COALESCE(r.rule, k.rule, json_extract(r.data_json, '$.rule')), r.data_json FROM review_results r
             LEFT JOIN passive_keys k ON k.finding_id = json_extract(r.data_json, '$.id')
             WHERE r.task_id = ?1 ORDER BY r.severity DESC, r.key LIMIT 10001",
        )?;
        let mut rows = stmt.query(params![id.0])?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next()? {
            ensure!(
                findings.len() < 10_000,
                "the report exceeds 10,000 findings"
            );
            let data: String = row.get(1)?;
            let finding: Finding = serde_json::from_str(&data)?;
            findings.push(ReportEntry {
                id: (finding.id.0 > 0).then_some(finding.id),
                rule: safe_rule(row.get(0)?),
                severity: finding.severity,
                confidence: finding.confidence,
                state: None,
                evidence: finding.evidence,
            });
        }
        Ok(FindingReport {
            schema_version: 1,
            run: Some(run),
            findings,
        })
    }
}

pub(super) fn safe_rule(rule: Option<String>) -> Option<String> {
    rule.filter(|rule| {
        (1..=80).contains(&rule.len())
            && rule
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

impl ReportRun {
    fn summary(&self) -> Vec<(&'static str, String)> {
        let mut rows = vec![
            ("Status", format!("{:?}", self.state)),
            ("Exchange limit", self.limit.to_string()),
            ("Exchanges examined", self.counts.examined.to_string()),
            ("Exchanges checked", self.counts.scanned.to_string()),
            (
                "Oversized exchanges skipped",
                self.counts.skipped_large.to_string(),
            ),
            ("Candidates omitted", self.counts.omitted.to_string()),
        ];
        if let Some((id, version)) = self.workflow_id.zip(self.workflow_version) {
            rows.push(("Workflow", format!("#{id} · Version {version}")));
        }
        if let Some(checks) = &self.check_ids {
            rows.push(("Passive checks", checks.join(", ")));
        }
        if let Some(archive) = &self.archive {
            if let Some(imported) = archive.imported {
                rows.push(("Imported exchanges", imported.to_string()));
                rows.push(("Import warnings", archive.warning_count.to_string()));
            } else {
                rows.push(("Capture import", "Incomplete".into()));
            }
            if let Some(format) = &archive.format {
                rows.push(("Capture format", format.clone()));
            }
            if let Some(hash) = &archive.sha256 {
                rows.push(("Capture SHA-256", hash.clone()));
            }
            if archive.reused {
                rows.push(("Capture storage", "Reused existing exchanges".into()));
            }
        }
        rows
    }
}

impl FindingReport {
    pub fn markdown(&self) -> String {
        let mut report = format!(
            "# {}\n\nRedacted summary. Evidence IDs refer to the local workspace.\n\n",
            self.heading()
        );
        if let Some(run) = &self.run {
            for (label, value) in run.summary() {
                report.push_str(&format!("- {label} · {value}\n"));
            }
            report.push('\n');
        }
        if self.findings.is_empty() {
            report.push_str("No findings in this report.\n");
            return report;
        }
        report.push_str("| ID | Check | Severity | Confidence | Status | Evidence IDs |\n");
        report.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for entry in &self.findings {
            let evidence = evidence_ids(entry);
            report.push_str(&format!(
                "| {} | {} | {:?} | {:?} | {} | {} |\n",
                entry.id.map_or_else(|| "—".into(), |id| id.to_string()),
                entry.rule.as_deref().unwrap_or("—"),
                entry.severity,
                entry.confidence,
                entry.state.map_or("Task result", ReviewState::as_str),
                evidence
            ));
        }
        report
    }

    fn heading(&self) -> String {
        self.run.as_ref().map_or_else(
            || "Camio findings".into(),
            |run| format!("Camio review #{}", run.id),
        )
    }
}

impl FindingReport {
    pub fn render(&self, format: ReportFormat) -> Result<String> {
        Ok(match format {
            ReportFormat::Markdown => self.markdown(),
            ReportFormat::Json => serde_json::to_string_pretty(self)?,
            ReportFormat::Html => self.html(),
            ReportFormat::Sarif => self.sarif()?,
        })
    }

    fn html(&self) -> String {
        let mut report = String::from(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>Camio findings</title><style>body{font:16px/1.5 system-ui;margin:2rem;max-width:72rem}\
             table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:.5rem;border-bottom:1px solid #bbb}\
             th{background:#eef4fc}code,dd{overflow-wrap:anywhere}</style><main>",
        );
        report.push_str(&format!(
            "<h1>{}</h1><p>Redacted summary. Evidence IDs refer to the local workspace.</p>",
            self.heading()
        ));
        if let Some(run) = &self.run {
            report.push_str("<dl>");
            for (label, value) in run.summary() {
                report.push_str(&format!("<dt>{label}</dt><dd>{}</dd>", html_text(&value)));
            }
            report.push_str("</dl>");
        }
        report.push_str("<table><thead><tr><th>ID</th><th>Check</th><th>Severity</th><th>Confidence</th><th>Status</th><th>Evidence IDs</th></tr></thead><tbody>");
        for entry in &self.findings {
            let check = entry.rule.as_deref().unwrap_or("—");
            let evidence = evidence_ids(entry);
            // Report entries obtained from Store contain only trusted rule
            // identifiers, but callers can also construct reports directly.
            let check = html_text(check);
            report.push_str(&format!(
                "<tr><td>{}</td><td><code>{check}</code></td><td>{:?}</td><td>{:?}</td><td>{}</td><td>{evidence}</td></tr>",
                entry.id.map_or_else(|| "—".into(), |id| id.to_string()), entry.severity, entry.confidence,
                entry.state.map_or("Task result", ReviewState::as_str),
            ));
        }
        if self.findings.is_empty() {
            report.push_str("<tr><td colspan=\"6\">No findings in this report.</td></tr>");
        }
        report.push_str("</tbody></table></main></html>\n");
        report
    }

    fn sarif(&self) -> Result<String> {
        let mut rules = BTreeSet::new();
        let mut results = Vec::with_capacity(self.findings.len());
        for entry in &self.findings {
            let check = entry.rule.as_deref().unwrap_or("recorded-finding");
            rules.insert(check);
            let level = match entry.severity {
                Severity::High | Severity::Critical => "error",
                Severity::Medium => "warning",
                Severity::Info | Severity::Low => "note",
            };
            results.push(json!({
                "ruleId": check,
                "level": level,
                "message": { "text": entry.id.map_or_else(|| check.to_owned(), |id| format!("{check} (finding #{id})")) },
                "properties": {
                    "camioFindingId": entry.id,
                    "camioSeverity": entry.severity,
                    "camioConfidence": entry.confidence,
                    "camioTriageStatus": entry.state,
                    "camioEvidenceIds": entry.evidence,
                },
            }));
        }
        let rules: Vec<_> = rules.into_iter().map(|id| json!({ "id": id })).collect();
        let mut run = json!({
            "tool": { "driver": { "name": "Camio", "version": env!("CARGO_PKG_VERSION"), "rules": rules } },
            "results": results,
        });
        if let Some(review) = &self.run {
            run["properties"] = json!({"camioReview": review});
        }
        Ok(serde_json::to_string_pretty(
            &json!({ "version": "2.1.0", "runs": [run] }),
        )?)
    }
}

fn html_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn evidence_ids(entry: &ReportEntry) -> String {
    entry
        .evidence
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

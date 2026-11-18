use super::{sha256_hex, FindingReport, Store};
use anyhow::{ensure, Result};
use camio_core::{ExchangeId, TaskId};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvidenceBundle {
    pub schema_version: u8,
    pub report: FindingReport,
    pub evidence: Vec<RedactedExchange>,
    pub manifest: EvidenceManifest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifest {
    pub report_sha256: String,
    pub exchanges: Vec<EvidenceDigest>,
    pub unavailable: Vec<ExchangeId>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDigest {
    pub id: ExchangeId,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedExchange {
    pub id: ExchangeId,
    pub source: String,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub request_bytes: i64,
    pub response_bytes: Option<i64>,
}

impl Store {
    pub fn review_evidence_bundle(&self, task: TaskId) -> Result<ReviewEvidenceBundle> {
        let report = self.review_report(task)?;
        let mut stmt = self.conn.prepare(
            "SELECT source, method, resp_status, req_len, resp_len FROM exchanges WHERE id = ?1",
        )?;
        let mut evidence = Vec::new();
        let mut exchanges = Vec::new();
        let mut unavailable = Vec::new();
        for id in evidence_ids(&report) {
            let record = stmt
                .query_row([id.0], |row| {
                    let method: String = row.get(1)?;
                    Ok(RedactedExchange {
                        id,
                        source: row.get(0)?,
                        method: method_name(&method).map(str::to_owned),
                        status: row.get(2)?,
                        request_bytes: row.get(3)?,
                        response_bytes: row.get(4)?,
                    })
                })
                .optional()?;
            if let Some(record) = record {
                exchanges.push(EvidenceDigest {
                    id,
                    sha256: digest(&record)?,
                });
                evidence.push(record);
            } else {
                unavailable.push(id);
            }
        }
        let manifest = EvidenceManifest {
            report_sha256: digest(&report)?,
            exchanges,
            unavailable,
        };
        Ok(ReviewEvidenceBundle {
            schema_version: 1,
            report,
            evidence,
            manifest,
        })
    }
}

impl ReviewEvidenceBundle {
    pub fn verified_json(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() as u64 <= MAX_BUNDLE_BYTES,
            "evidence bundles support up to 16 MiB"
        );
        let bundle: Self = serde_json::from_slice(data)?;
        // Compare JSON values so harmless whitespace and property ordering can
        // change while unrecognized fields still cause verification to fail.
        ensure!(
            serde_json::from_slice::<serde_json::Value>(data)? == serde_json::to_value(&bundle)?,
            "unexpected fields in evidence bundle"
        );
        bundle.verify()?;
        Ok(bundle)
    }

    pub fn verify(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.report.run.is_some(),
            "expected a version 1 review evidence bundle"
        );
        ensure!(
            self.manifest.report_sha256 == digest(&self.report)?,
            "report checksum mismatch"
        );
        ensure!(
            self.manifest.exchanges.len() == self.evidence.len(),
            "evidence manifest does not match the bundle"
        );
        let mut remaining = evidence_ids(&self.report);
        for (record, expected) in self.evidence.iter().zip(&self.manifest.exchanges) {
            ensure!(
                record.id == expected.id && remaining.remove(&record.id),
                "unexpected or repeated evidence ID {}",
                record.id
            );
            ensure!(
                digest(record)? == expected.sha256,
                "checksum mismatch for exchange {}",
                record.id
            );
        }
        for id in &self.manifest.unavailable {
            ensure!(
                remaining.remove(id),
                "unexpected or repeated unavailable evidence ID {id}"
            );
        }
        ensure!(
            remaining.is_empty(),
            "the bundle is missing evidence referenced by the report"
        );
        Ok(())
    }
}

fn evidence_ids(report: &FindingReport) -> BTreeSet<ExchangeId> {
    report
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().copied())
        .collect()
}

fn digest(value: &impl Serialize) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

fn method_name(value: &str) -> Option<&str> {
    matches!(
        value,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE"
    )
    .then_some(value)
}

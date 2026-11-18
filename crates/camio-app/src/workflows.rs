use super::{CamioApp, Output};
use camio_store::{ReviewPlan, ReviewWorkflow, WorkflowVersion, MAX_REVIEW_EXCHANGES};
use egui::{RichText, Stroke};

pub(super) struct WorkflowView {
    catalog: Vec<ReviewWorkflow>,
    versions: Vec<WorkflowVersion>,
    saved: Option<ReviewWorkflow>,
    name: String,
    draft: ReviewPlan,
    available_checks: Vec<camio_scan::ReviewCheck>,
    archive_path: String,
    json: String,
    json_dirty: bool,
}

impl Default for WorkflowView {
    fn default() -> Self {
        let draft = ReviewPlan::new("", 200, true);
        let json = serde_json::to_string_pretty(&draft).unwrap_or_default();
        Self {
            catalog: Vec::new(),
            versions: Vec::new(),
            saved: None,
            name: String::new(),
            draft,
            available_checks: camio_scan::review_checks(),
            archive_path: String::new(),
            json,
            json_dirty: false,
        }
    }
}

impl WorkflowView {
    fn load(&mut self, saved: Option<ReviewWorkflow>, versions: Vec<WorkflowVersion>) {
        self.name = saved
            .as_ref()
            .map(|flow| flow.revision.name.clone())
            .unwrap_or_default();
        self.draft = saved
            .as_ref()
            .map(|flow| flow.plan.clone())
            .unwrap_or_else(|| ReviewPlan::new("", 200, true));
        self.versions = versions;
        self.saved = saved;
        self.json_dirty = false;
        self.sync_json();
    }

    fn sync_json(&mut self) {
        if !self.json_dirty {
            self.json = serde_json::to_string_pretty(&self.draft).unwrap_or_default();
        }
    }

    fn unchanged(&self) -> Option<&WorkflowVersion> {
        let saved = self.saved.as_ref()?;
        (!self.json_dirty
            && self.name.trim() == saved.revision.name
            && self.draft.query.trim() == saved.plan.query
            && self.draft.limit == saved.plan.limit
            && self.draft.save == saved.plan.save
            && self.draft.schema_version == saved.plan.schema_version
            && self.draft.check_ids == saved.plan.check_ids)
            .then_some(&saved.revision)
    }
}

impl CamioApp {
    pub(super) fn refresh_workflows(&mut self) {
        match self
            .open()
            .and_then(|store| store.review_workflows().map_err(|error| error.to_string()))
        {
            Ok(catalog) => self.workflows.catalog = catalog,
            Err(error) => self.out = Output::Error(error),
        }
    }

    fn load_workflow(&mut self, id: i64, version: Option<i64>) {
        let result = self.open().and_then(|store| {
            let flow = store
                .review_workflow(id, version)
                .map_err(|error| error.to_string())?
                .ok_or("Workflow version was not found.")?;
            let versions = store
                .review_workflow_versions(id)
                .map_err(|error| error.to_string())?;
            Ok((flow, versions))
        });
        match result {
            Ok((flow, versions)) => {
                self.workflows.load(Some(flow), versions);
                self.out = Output::None;
            }
            Err(error) => self.out = Output::Error(error),
        }
    }

    fn save_workflow(&mut self) {
        if let Err(error) = camio_scan::validate_review_plan(&self.workflows.draft) {
            self.out = Output::Error(format!("{error:#}"));
            return;
        }
        let result = self.open().and_then(|mut store| {
            let flow = store
                .save_review_workflow(&self.workflows.name, &self.workflows.draft)
                .map_err(|error| format!("{error:#}"))?;
            let versions = store
                .review_workflow_versions(flow.revision.id)
                .map_err(|error| error.to_string())?;
            Ok((flow, versions))
        });
        match result {
            Ok((flow, versions)) => {
                self.out = Output::Text(format!(
                    "Saved {} · Version {}",
                    flow.revision.name, flow.revision.version
                ));
                self.workflows.load(Some(flow), versions);
                self.refresh_workflows();
            }
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn workflows_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Review workflows");
        ui.label("Version a review of stored traffic so you can repeat it with the same filter and limits.");
        let mut next = None;
        ui.horizontal_wrapped(|ui| {
            let saved = self.workflows.saved.as_ref().map(|flow| &flow.revision);
            egui::ComboBox::from_id_salt("workflow")
                .selected_text(saved.map_or("New workflow", |flow| flow.name.as_str()))
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(saved.is_none(), "New workflow")
                        .clicked()
                    {
                        next = Some(None);
                    }
                    for workflow in &self.workflows.catalog {
                        let info = &workflow.revision;
                        if ui
                            .selectable_label(
                                saved.is_some_and(|rev| rev.id == info.id),
                                &info.name,
                            )
                            .clicked()
                        {
                            next = Some(Some((info.id, None)));
                        }
                    }
                });
            if let Some(saved) = saved {
                egui::ComboBox::from_id_salt("workflow-version")
                    .selected_text(format!("Version {}", saved.version))
                    .show_ui(ui, |ui| {
                        for version in &self.workflows.versions {
                            if ui
                                .selectable_label(
                                    saved.version == version.version,
                                    format!("Version {}", version.version),
                                )
                                .clicked()
                            {
                                next = Some(Some((saved.id, Some(version.version))));
                            }
                        }
                    });
            }
        });
        match next {
            Some(Some((id, version))) => self.load_workflow(id, version),
            Some(None) => {
                self.workflows.load(None, Vec::new());
                self.out = Output::None;
            }
            None => {}
        }

        ui.horizontal_wrapped(|ui| {
            ui.label("Workflow name");
            ui.add(
                egui::TextEdit::singleline(&mut self.workflows.name)
                    .char_limit(100)
                    .desired_width(210.0),
            );
            ui.label("Recent exchanges");
            if ui
                .add(
                    egui::DragValue::new(&mut self.workflows.draft.limit)
                        .range(1..=MAX_REVIEW_EXCHANGES),
                )
                .changed()
            {
                self.workflows.sync_json();
            }
        });
        ui.label("CamioQL filter");
        if ui
            .add(
                egui::TextEdit::singleline(&mut self.workflows.draft.query)
                    .desired_width(f32::INFINITY)
                    .hint_text("Every exchange in the review window"),
            )
            .changed()
        {
            self.workflows.sync_json();
        }
        if ui
            .checkbox(&mut self.workflows.draft.save, "Add findings to triage")
            .changed()
        {
            self.workflows.sync_json();
        }
        self.workflow_check_settings(ui);
        ui.label("Capture archive path (optional)");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.workflows.archive_path)
                    .hint_text("HAR or Burp items XML")
                    .desired_width(300.0),
            );
            if !self.workflows.archive_path.is_empty() && ui.button("Clear archive").clicked() {
                self.workflows.archive_path.clear();
            }
        });
        self.workflow_steps(ui);

        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.workflows.json_dirty,
                    egui::Button::new("Save workflow version"),
                )
                .clicked()
            {
                self.save_workflow();
            }
            let selection = self.workflows.unchanged().cloned();
            let archive = self.workflows.archive_path.trim();
            let source = if archive.is_empty() {
                ""
            } else {
                " on archive"
            };
            let run_label = selection
                .as_ref()
                .map(|flow| format!("Run version {}{source}", flow.version))
                .unwrap_or_else(|| "Run saved version".into());
            let run = ui.add_enabled(selection.is_some(), egui::Button::new(run_label));
            if let Some(version) = selection.filter(|_| run.clicked()) {
                let result = if archive.is_empty() {
                    camio_scan::start_review_workflow(
                        &self.cfg.db,
                        version.id,
                        Some(version.version),
                    )
                } else {
                    camio_scan::start_archive_review(
                        &self.cfg.db,
                        version.id,
                        Some(version.version),
                        camio_scan::ReviewArchiveInput::File(archive.into()),
                    )
                };
                match result {
                    Ok(task) => self.open_review(task),
                    Err(error) => self.out = Output::Error(format!("{error:#}")),
                }
            }
        });
        ui.collapsing("Plan JSON", |ui| {
            ui.label("Apply JSON edits to the draft before saving a version.");
            if ui
                .add(
                    egui::TextEdit::multiline(&mut self.workflows.json)
                        .desired_width(f32::INFINITY)
                        .code_editor()
                        .desired_rows(7),
                )
                .changed()
            {
                self.workflows.json_dirty = true;
            }
            ui.horizontal(|ui| {
                if ui.button("Apply JSON to draft").clicked() {
                    let parsed = (|| {
                        let plan: ReviewPlan = serde_json::from_str(&self.workflows.json)?;
                        camio_scan::validate_review_plan(&plan)?;
                        Ok::<_, anyhow::Error>(plan)
                    })();
                    match parsed {
                        Ok(plan) => {
                            self.workflows.draft = plan;
                            self.workflows.json_dirty = false;
                            self.workflows.sync_json();
                            self.out = Output::Text("JSON plan applied to the draft.".into());
                        }
                        Err(error) => self.out = Output::Error(format!("{error:#}")),
                    }
                }
                if ui.button("Copy plan JSON").clicked() {
                    ui.ctx().copy_text(self.workflows.json.clone());
                }
            });
        });
    }

    fn workflow_check_settings(&mut self, ui: &mut egui::Ui) {
        let pane = &mut self.workflows;
        let all = &pane.available_checks;
        let count = pane.draft.check_ids.as_ref().map_or(all.len(), Vec::len);
        let mut changed = false;
        ui.collapsing(format!("Passive checks · {count} selected"), |ui| {
            let mut selected = pane
                .draft
                .check_ids
                .clone()
                .unwrap_or_else(|| all.iter().map(|check| check.id.to_owned()).collect());
            ui.horizontal(|ui| {
                if ui.button("Select all").clicked() {
                    selected = all.iter().map(|check| check.id.to_owned()).collect();
                    changed = true;
                }
                if ui.button("Clear checks").clicked() {
                    selected.clear();
                    changed = true;
                }
            });
            for check in all {
                let mut checked = selected.iter().any(|id| id == check.id);
                if ui
                    .checkbox(&mut checked, check.title)
                    .on_hover_text(check.id)
                    .changed()
                {
                    changed = true;
                    if checked {
                        selected.push(check.id.to_owned());
                    } else {
                        selected.retain(|id| id != check.id);
                    }
                }
            }
            if changed {
                selected.sort();
                pane.draft.check_ids = (selected.len() != all.len()).then_some(selected);
                pane.draft.schema_version = if pane.draft.check_ids.is_some() { 2 } else { 1 };
            }
        });
        if changed {
            pane.sync_json();
        }
    }

    fn workflow_steps(&self, ui: &mut egui::Ui) {
        let draft = &self.workflows.draft;
        let count = format!("Up to {} exchanges", draft.limit);
        let configured = draft.check_ids.as_ref().map_or_else(
            || "All built-in checks".into(),
            |checks| format!("{} selected", checks.len()),
        );
        let source = if self.workflows.archive_path.trim().is_empty() {
            "Stored traffic"
        } else {
            "Import capture"
        };
        let steps = [
            (source, count.as_str()),
            (
                "CamioQL filter",
                if draft.query.is_empty() {
                    "All in review window"
                } else {
                    draft.query.as_str()
                },
            ),
            ("Passive checks", configured.as_str()),
            (
                "Findings",
                if draft.save {
                    "Save to triage"
                } else {
                    "Keep in task results"
                },
            ),
        ];
        ui.add_space(5.0);
        ui.columns(steps.len(), |columns| {
            for (column, (title, detail)) in columns.iter_mut().zip(steps) {
                let inset = 8.0;
                let width = (column.available_width() - 2.0 * inset).max(25.0);
                egui::Frame::none()
                    .fill(self.theme.panel_color())
                    .rounding(self.theme.rounding)
                    .stroke(Stroke::new(
                        1.0_f32,
                        self.theme.accent_color().gamma_multiply(0.45),
                    ))
                    .inner_margin(egui::Margin::same(inset))
                    .show(column, |ui| {
                        ui.set_width(width);
                        ui.set_min_height(64.0);
                        ui.label(RichText::new(title).strong());
                        ui.add(
                            egui::Label::new(RichText::new(detail).monospace().small()).truncate(),
                        );
                    });
            }
        });
    }
}

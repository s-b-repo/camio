use super::{CamioApp, Output, Surface};
use camio_core::{ExchangeId, Finding, FindingId, Query, TaskId, TaskState};
use camio_store::{
    ArtifactFormat, ArtifactSummary, ExchangePreview, FindingReview, HistoryPage, Observation,
    ReportFormat, ReviewState, ReviewTask, SavedExchange, SavedQuery, WorkspaceSummary,
    ARTIFACT_BYTES,
};
use egui::{Color32, RichText, Stroke};
use std::io::Read;
use std::time::{Duration, Instant};

pub(super) const NAV: &[(&str, &[(Surface, &str)])] = &[
    (
        "Workspace",
        &[
            (Surface::Status, "Overview"),
            (Surface::Workflows, "Review workflows"),
            (Surface::Tasks, "Review tasks"),
            (Surface::Library, "Library"),
        ],
    ),
    (
        "Traffic",
        &[
            (Surface::History, "History"),
            (Surface::Query, "CamioQL"),
            (Surface::Sitemap, "Site map"),
            (Surface::Inventory, "Asset inventory"),
            (Surface::Replay, "Replay"),
            (Surface::Discover, "Discover inputs"),
            (Surface::MatchReplace, "Match & Replace"),
            (Surface::Browser, "Open browser"),
        ],
    ),
    (
        "Review",
        &[
            (Surface::Scan, "Passive review"),
            (Surface::Findings, "Findings"),
            (Surface::Import, "Import traffic"),
            (Surface::Integrations, "Integration evidence"),
            (Surface::Fuzz, "Automate / Fuzz"),
            (Surface::ActiveScan, "Active scan"),
        ],
    ),
    (
        "Utilities",
        &[
            (Surface::Convert, "Convert"),
            (Surface::Comparer, "Comparer"),
            (Surface::Jwt, "JWT decode"),
            (Surface::Sequencer, "Sequencer"),
            (Surface::AnalyzeJs, "Analyze JS"),
            (Surface::Scope, "Scope check"),
            (Surface::Payloads, "Payloads"),
            (Surface::Ai, "AI assistant"),
        ],
    ),
    (
        "Settings",
        &[
            (Surface::Fingerprint, "Transport"),
            (Surface::Plugins, "Plugins"),
            (Surface::Settings, "Workspace settings"),
        ],
    ),
];

pub(super) fn title(surface: Surface) -> &'static str {
    NAV.iter()
        .flat_map(|(_, items)| items.iter())
        .find(|(item, _)| *item == surface)
        .map(|(_, label)| *label)
        .unwrap_or("Overview")
}

pub(super) struct Workbench {
    summary: Option<WorkspaceSummary>,
    recent: Vec<camio_store::HistoryRow>,
    workspace_name: String,
    pub(super) command_open: bool,
    command_query: String,
    command_focus: bool,
    pub(super) history: HistoryView,
    inspector: Option<Inspector>,
    findings: Vec<FindingReview>,
    finding_offset: usize,
    review_filter: Option<ReviewState>,
    finding_draft: Option<(FindingId, ReviewState, String)>,
    review_tasks: Vec<ReviewTask>,
    review_selection: Option<TaskId>,
    task_offset: usize,
    task_findings: Vec<Finding>,
    tasks_checked: Option<Instant>,
    artifact_format: ArtifactFormat,
    artifacts: Vec<ArtifactSummary>,
    artifact_before: Option<i64>,
    artifact_selected: Option<i64>,
    artifact_cursor: Option<i64>,
    artifact_next: Option<i64>,
    artifact_rows: Vec<Observation>,
    artifact_version: String,
    artifact_path: String,
    artifact_text: String,
    saved_name: String,
    saved_queries: Vec<SavedQuery>,
    saved_exchanges: Vec<SavedExchange>,
    library_offset: usize,
    review_limit: usize,
}

impl Default for Workbench {
    fn default() -> Self {
        Self {
            summary: None,
            recent: Vec::new(),
            workspace_name: String::new(),
            command_open: false,
            command_query: String::new(),
            command_focus: false,
            history: HistoryView::default(),
            inspector: None,
            findings: Vec::new(),
            finding_offset: 0,
            review_filter: None,
            finding_draft: None,
            review_tasks: Vec::new(),
            review_selection: None,
            task_offset: 0,
            task_findings: Vec::new(),
            tasks_checked: None,
            artifact_format: ArtifactFormat::Httpx,
            artifacts: Vec::new(),
            artifact_before: None,
            artifact_selected: None,
            artifact_cursor: None,
            artifact_next: None,
            artifact_rows: Vec::new(),
            artifact_version: String::new(),
            artifact_path: String::new(),
            artifact_text: String::new(),
            saved_name: String::new(),
            saved_queries: Vec::new(),
            saved_exchanges: Vec::new(),
            library_offset: 0,
            review_limit: 200,
        }
    }
}

#[derive(Default)]
pub(super) struct HistoryView {
    page: Option<HistoryPage>,
    before: Vec<Option<ExchangeId>>,
    filter: String,
    limit: usize,
}

impl HistoryView {
    pub(super) fn invalidate(&mut self) {
        self.page = None;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MessageView {
    Structured,
    Raw,
    Hex,
}

struct Inspector {
    preview: ExchangePreview,
    response: bool,
    view: MessageView,
    label: String,
    note: String,
    saved: bool,
    notice: Option<Result<String, String>>,
}

impl CamioApp {
    pub(super) fn enter_workbench(&mut self, surface: Surface) {
        match surface {
            Surface::Status => self.refresh_overview(),
            Surface::Workflows => self.refresh_workflows(),
            Surface::Inventory => self.refresh_inventory(),
            Surface::History | Surface::Query => {
                if self.workbench.history.page.is_none() {
                    self.refresh_history(true);
                }
                self.reload_queries();
            }
            Surface::Tasks => self.refresh_tasks(),
            Surface::Findings => self.refresh_findings(),
            Surface::Integrations => self.refresh_artifacts(),
            Surface::Library => {
                self.reload_queries();
                self.reload_saved_exchanges();
            }
            Surface::Settings if self.workbench.summary.is_none() => self.refresh_overview(),
            _ => {}
        }
    }

    fn refresh_overview(&mut self) {
        match self.open().and_then(|store| {
            let all = Query::compile("").expect("empty filter");
            Ok((
                store.workspace().map_err(message)?,
                store
                    .history_page(&all, None, 5)
                    .map_err(message)?
                    .exchanges,
            ))
        }) {
            Ok((summary, recent)) => {
                self.workbench
                    .workspace_name
                    .clone_from(&summary.project.name);
                self.workbench.summary = Some(summary);
                self.workbench.recent = recent;
            }
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn overview_ui(&mut self, ui: &mut egui::Ui) {
        let accent = self.theme.accent_color();
        let rounds = egui::Rounding::same(self.theme.rounding);
        let panel = self.theme.panel_color();
        let heading = self
            .workbench
            .summary
            .as_ref()
            .map(|workspace| workspace.project.name.as_str())
            .unwrap_or("Local workspace")
            .to_string();
        let paint = ui.painter().add(egui::Shape::Noop);
        let grid = ui.painter().add(egui::Shape::Noop);
        let frame = egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(18.0, 13.0))
            .show(ui, |ui| {
                ui.set_min_width((ui.available_width() - 2.0).max(100.0));
                ui.columns(2, |columns| {
                    columns[0].label(RichText::new("WORKSPACE OVERVIEW").size(10.0).monospace());
                    columns[0].label(RichText::new(&heading).size(35.0).strong());
                    columns[0].label("Review stored traffic and the findings it supports.");
                    columns[0].add_space(8.0);
                    columns[0].horizontal_wrapped(|ui| {
                        if ui.button("Import traffic").clicked() {
                            self.navigate(Surface::Import);
                        }
                        if ui.button("Browse history").clicked() {
                            self.navigate(Surface::History);
                        }
                    });
                    columns[1].add_space(3.0);
                    egui::Frame::none()
                        .fill(panel)
                        .rounding(rounds)
                        .stroke(Stroke::new(1.0_f32, accent.gamma_multiply(0.55)))
                        .inner_margin(egui::Margin::same(11.0))
                        .show(&mut columns[1], |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.label(
                                RichText::new("REQUEST TRANSPORT")
                                    .monospace()
                                    .size(10.0)
                                    .strong(),
                            );
                            ui.separator();
                            ui.label(format!("Profile    {}", self.cfg.profile.name));
                            ui.label(format!("Engine     {}", self.engine.label()));
                            ui.label("Measured parity    Unverified");
                        });
                });
            });
        let rect = frame.response.rect;
        let tint = accent.gamma_multiply(if self.theme.dark { 0.17 } else { 0.06 });
        let fill = egui::lerp(
            egui::Rgba::from(panel)..=egui::Rgba::from(accent),
            if self.theme.dark { 0.045 } else { 0.05 },
        );
        let grid_rect = rect.shrink(3.0);

        // The sweep lives on the right side of the overview and stops when the
        // window loses focus or Reduce motion is selected.
        let mut lines = Vec::new();
        let left = grid_rect.center().x - 22.0;
        let mut x = left;
        while x < grid_rect.right() {
            lines.push(egui::Shape::line_segment(
                [
                    egui::pos2(x, grid_rect.top()),
                    egui::pos2(x, grid_rect.bottom()),
                ],
                Stroke::new(1.0_f32, tint),
            ));
            x += 23.0;
        }
        let mut y = grid_rect.top() + 16.0;
        while y < grid_rect.bottom() {
            lines.push(egui::Shape::line_segment(
                [egui::pos2(left, y), egui::pos2(grid_rect.right(), y)],
                Stroke::new(1.0_f32, tint),
            ));
            y += 23.0;
        }
        if self.theme.motion && ui.ctx().input(|input| input.focused) {
            let phase = ui.input(|input| (input.time / 7.0).fract() as f32);
            let x = egui::lerp(left..=grid_rect.right(), phase);
            let glow = (std::f32::consts::PI * phase).sin() * 0.22;
            lines.push(egui::Shape::line_segment(
                [
                    egui::pos2(x, grid_rect.top()),
                    egui::pos2(x, grid_rect.bottom()),
                ],
                Stroke::new(2.0_f32, accent.gamma_multiply(glow)),
            ));
            ui.ctx().request_repaint_after(Duration::from_millis(45));
        }
        ui.painter().set(grid, egui::Shape::Vec(lines));
        // Place the grid below the foreground content.
        let background = egui::Shape::Vec(vec![
            egui::Shape::rect_filled(rect, rounds, Color32::from(fill)),
            egui::Shape::rect_stroke(
                rect,
                rounds,
                Stroke::new(1.0_f32, accent.gamma_multiply(0.55)),
            ),
        ]);
        ui.painter().set(paint, background);

        ui.add_space(7.0);
        if let Some(summary) = &self.workbench.summary {
            let cards = [
                ("Exchanges", summary.exchanges, Surface::History),
                ("Open findings", summary.open_findings, Surface::Findings),
                (
                    "Imported artifacts",
                    summary.artifacts,
                    Surface::Integrations,
                ),
                ("Saved exchanges", summary.saved_exchanges, Surface::Library),
            ];
            ui.columns(cards.len(), |columns| {
                for (column, (label, count, surface)) in columns.iter_mut().zip(cards) {
                    let label = RichText::new(format!("{count}\n{label}"))
                        .size(15.0)
                        .strong();
                    if column
                        .add_sized(
                            [column.available_width(), 58.0],
                            egui::Button::new(label).fill(panel),
                        )
                        .clicked()
                    {
                        self.navigate(surface);
                    }
                }
            });
        }

        ui.add_space(12.0);
        egui::Frame::none()
            .fill(panel)
            .rounding(rounds)
            .stroke(ui.visuals().window_stroke)
            .inner_margin(egui::Margin::same(13.0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.heading("Recent traffic");
                    if ui.button("Refresh").clicked() {
                        self.refresh_overview();
                    }
                    if ui.button("Review tasks").clicked() {
                        self.navigate(Surface::Tasks);
                    }
                });
                ui.separator();
                if self.workbench.recent.is_empty() {
                    ui.label("No traffic has been recorded here.");
                }
                if let Some(id) = history_rows(ui, &self.workbench.recent, 150.0, "recent") {
                    self.open_inspector(id);
                }
            });
    }

    pub(super) fn command_ui(&mut self, ctx: &egui::Context) {
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::K)) {
            self.workbench.command_open = !self.workbench.command_open;
            self.workbench.command_focus = self.workbench.command_open;
        }
        if !self.workbench.command_open {
            return;
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            self.workbench.command_open = false;
            return;
        }

        let mut open = self.workbench.command_open;
        let mut selected = None;
        egui::Window::new("Search tools")
            .id(egui::Id::new("commands"))
            .open(&mut open)
            .default_width(350.0)
            .anchor(egui::Align2::CENTER_TOP, [0.0, 86.0])
            .resizable(false)
            .show(ctx, |ui| {
                let input = ui.add(
                    egui::TextEdit::singleline(&mut self.workbench.command_query)
                        .hint_text("Find a tool or workspace view…")
                        .desired_width(f32::INFINITY),
                );
                if std::mem::take(&mut self.workbench.command_focus) {
                    input.request_focus();
                }
                let term = self.workbench.command_query.to_lowercase();
                let mut matches = NAV
                    .iter()
                    .flat_map(|(_, items)| items.iter())
                    .filter(|(_, label)| label.to_lowercase().contains(&term))
                    .peekable();
                let enter =
                    input.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                if enter {
                    selected = matches.peek().map(|(surface, _)| *surface);
                }
                if matches.peek().is_none() {
                    ui.label("No tools match.");
                }
                egui::ScrollArea::vertical()
                    .max_height(320.0)
                    .show(ui, |ui| {
                        for (surface, label) in matches {
                            if ui
                                .selectable_label(self.surface == *surface, *label)
                                .clicked()
                            {
                                selected = Some(*surface);
                            }
                        }
                    });
            });
        self.workbench.command_open = open && selected.is_none();
        if let Some(surface) = selected {
            self.navigate(surface);
        }
    }

    pub(super) fn toggle_command(&mut self) {
        self.workbench.command_open = !self.workbench.command_open;
        self.workbench.command_focus = self.workbench.command_open;
    }

    fn reload_queries(&mut self) {
        match self
            .open()
            .and_then(|store| store.saved_queries().map_err(message))
        {
            Ok(queries) => self.workbench.saved_queries = queries,
            Err(error) => self.out = Output::Error(error),
        }
    }

    fn refresh_history(&mut self, reset: bool) {
        if reset {
            self.workbench.history.before = vec![None];
            self.workbench.history.filter = self.query.trim().to_owned();
            self.workbench.history.limit = self.limit_usize(50).clamp(1, 200);
        }
        let history = &self.workbench.history;
        let result = self.open().and_then(|store| {
            if history.filter.len() > 1024 {
                return Err("CamioQL filters support up to 1024 bytes.".into());
            }
            let query = Query::compile(&history.filter).map_err(message)?;
            store
                .history_page(
                    &query,
                    history.before.last().copied().flatten(),
                    history.limit,
                )
                .map_err(message)
        });
        match result {
            Ok(page) => {
                self.workbench.history.page = Some(page);
                self.out = Output::None;
            }
            Err(error) => {
                self.workbench.history.page = None;
                self.out = Output::Error(error);
            }
        }
    }

    pub(super) fn history_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(title(self.surface));
        ui.label("Review stored exchanges or filter by method, URL, headers, and body.");
        ui.horizontal(|ui| {
            ui.label("CamioQL");
            let input = ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text("resp.code.gte:400")
                    .desired_width((ui.available_width() - 145.0).max(70.0)),
            );
            if ui.button("Apply").clicked()
                || (input.lost_focus() && ui.input(|state| state.key_pressed(egui::Key::Enter)))
            {
                self.refresh_history(true);
            }
            if ui.button("Clear").clicked() {
                self.query.clear();
                self.refresh_history(true);
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Page size");
            ui.add(egui::TextEdit::singleline(&mut self.limit).desired_width(42.0));
            let mut use_query = None;
            egui::ComboBox::from_id_salt("saved-filter")
                .selected_text("Saved queries")
                .show_ui(ui, |ui| {
                    if self.workbench.saved_queries.is_empty() {
                        ui.label("No saved queries");
                    }
                    for query in &self.workbench.saved_queries {
                        if ui.selectable_label(false, &query.name).clicked() {
                            use_query = Some(query.expression.clone());
                        }
                    }
                });
            if let Some(expression) = use_query {
                self.query = expression;
                self.refresh_history(true);
            }
        });
        ui.collapsing("Save filter to the library", |ui| {
            ui.horizontal(|ui| {
                ui.label("Query name");
                ui.add(
                    egui::TextEdit::singleline(&mut self.workbench.saved_name).desired_width(180.0),
                );
                if ui.button("Save query").clicked() {
                    let result = self.open().and_then(|store| {
                        store
                            .save_query(&self.workbench.saved_name, &self.query)
                            .map_err(message)
                    });
                    if result.is_ok() {
                        self.workbench.saved_name.clear();
                        self.reload_queries();
                    }
                    self.operation(result, "Query saved.");
                }
            });
        });

        if let Some(page) = &self.workbench.history.page {
            let next = page.next_before;
            let mut step = None;
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{} exchanges · Page {}",
                    page.exchanges.len(),
                    self.workbench.history.before.len()
                ));
                if page.skipped_large > 0 {
                    ui.label(format!(
                        "{} oversized exchanges skipped",
                        page.skipped_large
                    ));
                }
                if ui
                    .add_enabled(
                        self.workbench.history.before.len() > 1,
                        egui::Button::new("Previous"),
                    )
                    .clicked()
                {
                    step = Some(None);
                }
                if ui
                    .add_enabled(next.is_some(), egui::Button::new("Next"))
                    .clicked()
                {
                    step = Some(next);
                }
            });
            if let Some(cursor) = step {
                if let Some(cursor) = cursor {
                    self.workbench.history.before.push(Some(cursor));
                } else {
                    self.workbench.history.before.pop();
                }
                self.refresh_history(false);
            }
            if let Some(page) = &self.workbench.history.page {
                if page.exchanges.is_empty() {
                    ui.label("No exchanges on this page.");
                }
                if let Some(id) = history_rows(ui, &page.exchanges, 440.0, "history-page") {
                    self.open_inspector(id);
                }
            }
        }
    }

    pub(super) fn open_inspector(&mut self, id: ExchangeId) {
        match self.open().and_then(|store| {
            let preview = store
                .inspect_exchange(id)
                .map_err(message)?
                .ok_or("Exchange was not found.")?;
            let saved = store.saved_exchange(id).map_err(message)?;
            Ok((preview, saved))
        }) {
            Ok((preview, saved)) => {
                let is_saved = saved.is_some();
                let (label, note) = saved
                    .map(|entry| (entry.label, entry.note))
                    .unwrap_or_default();
                self.workbench.inspector = Some(Inspector {
                    preview,
                    response: false,
                    view: MessageView::Structured,
                    label,
                    note,
                    saved: is_saved,
                    notice: None,
                });
            }
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn inspector_ui(&mut self, ctx: &egui::Context) {
        let Some(inspector) = &mut self.workbench.inspector else {
            return;
        };
        let mut open = true;
        let mut bookmark = None;
        let id = inspector.preview.exchange.id;
        egui::Window::new(format!("Exchange #{id}"))
            .id(egui::Id::new("exchange-inspector"))
            .open(&mut open)
            .default_width(680.0)
            .default_height(435.0)
            .vscroll(true)
            .show(ctx, |ui| {
                ui.label(RichText::new(&inspector.preview.exchange.request.url).monospace());
                ui.horizontal_wrapped(|ui| {
                    ui.selectable_value(&mut inspector.response, false, "Request");
                    if inspector.preview.exchange.response.is_some() {
                        ui.selectable_value(&mut inspector.response, true, "Response");
                    }
                    ui.separator();
                    for (view, name) in [
                        (MessageView::Structured, "Structured"),
                        (MessageView::Raw, "Raw"),
                        (MessageView::Hex, "Body hex"),
                    ] {
                        ui.selectable_value(&mut inspector.view, view, name);
                    }
                });
                message_view(ui, inspector);
                ui.collapsing("Save to library", |ui| {
                    ui.label("Label");
                    ui.text_edit_singleline(&mut inspector.label);
                    ui.label("Notes");
                    ui.text_edit_multiline(&mut inspector.note);
                    ui.horizontal(|ui| {
                        if ui.button("Save exchange").clicked() {
                            bookmark = Some(true);
                        }
                        if inspector.saved && ui.button("Remove saved exchange").clicked() {
                            bookmark = Some(false);
                        }
                    });
                    if let Some(result) = &inspector.notice {
                        match result {
                            Ok(note) => {
                                ui.label(note);
                            }
                            Err(error) => {
                                ui.colored_label(ui.visuals().error_fg_color, error);
                            }
                        }
                    }
                });
            });
        if !open {
            self.workbench.inspector = None;
        } else if let Some(save) = bookmark {
            let result = self.open().and_then(|store| {
                let inspector = self.workbench.inspector.as_ref().unwrap();
                if save {
                    store
                        .save_exchange(id, &inspector.label, &inspector.note)
                        .map_err(message)
                } else {
                    store.delete_saved_exchange(id).map_err(message)
                }
            });
            if result.is_ok() && self.surface == Surface::Library {
                self.reload_saved_exchanges();
            }
            if let Some(inspector) = self.workbench.inspector.as_mut() {
                if result.is_ok() {
                    inspector.saved = save;
                }
                inspector.notice = Some(result.map(|_| {
                    if save {
                        "Saved to the library.".into()
                    } else {
                        "Removed from the library.".into()
                    }
                }));
            }
        }
    }

    fn reload_saved_exchanges(&mut self) {
        match self.open().and_then(|store| {
            store
                .saved_exchanges(self.workbench.library_offset)
                .map_err(message)
        }) {
            Ok(exchanges) => self.workbench.saved_exchanges = exchanges,
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn scan_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Passive review");
        ui.label("Run built-in checks on already stored traffic.");
        ui.label("CamioQL filter");
        ui.add(
            egui::TextEdit::singleline(&mut self.query)
                .hint_text("Every exchange in the review window")
                .desired_width(f32::INFINITY),
        );
        ui.horizontal_wrapped(|ui| {
            ui.label("Recent exchanges to examine");
            ui.add(
                egui::DragValue::new(&mut self.workbench.review_limit)
                    .range(1..=camio_scan::MAX_REVIEW_EXCHANGES),
            );
            ui.checkbox(&mut self.scan_save, "Add findings to triage");
        });
        if ui.button("Start review").clicked() {
            match camio_scan::start_passive_review(
                &self.cfg.db,
                &self.query,
                self.workbench.review_limit,
                self.scan_save,
            ) {
                Ok(id) => self.open_review(id),
                Err(error) => self.out = Output::Error(format!("{error:#}")),
            }
        }
    }

    pub(super) fn open_review(&mut self, id: TaskId) {
        self.workbench.review_selection = Some(id);
        self.workbench.task_offset = 0;
        self.navigate(Surface::Tasks);
    }

    fn refresh_tasks(&mut self) {
        self.workbench.tasks_checked = Some(Instant::now());
        match self.open().and_then(|store| {
            let tasks = store.review_tasks().map_err(message)?;
            let selection = self
                .workbench
                .review_selection
                .or_else(|| tasks.first().map(|task| task.task.id));
            let findings = match selection {
                Some(id) => store
                    .review_results(id, self.workbench.task_offset)
                    .map_err(message)?,
                None => Vec::new(),
            };
            Ok((tasks, selection, findings))
        }) {
            Ok((tasks, selection, findings)) => {
                let new_capture = selection
                    .and_then(|id| tasks.iter().find(|task| task.task.id == id))
                    .and_then(|task| task.archive.as_ref())
                    .is_some_and(|archive| archive.sha256.is_some() && !archive.reused);
                if new_capture
                    && !self.workbench.review_tasks.iter().any(|task| {
                        Some(task.task.id) == selection
                            && task
                                .archive
                                .as_ref()
                                .is_some_and(|archive| archive.sha256.is_some())
                    })
                {
                    self.workbench.history.invalidate();
                }
                self.workbench.review_tasks = tasks;
                self.workbench.review_selection = selection;
                self.workbench.task_findings = findings;
            }
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn tasks_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Review tasks");
        ui.horizontal_wrapped(|ui| {
            if ui.button("New passive review").clicked() {
                self.navigate(Surface::Scan);
            }
            if ui.button("Refresh").clicked() {
                self.refresh_tasks();
            }
        });
        let period = Duration::from_millis(900);
        if self.workbench.tasks_checked.is_none()
            || self
                .workbench
                .tasks_checked
                .is_some_and(|last| last.elapsed() >= period)
        {
            self.refresh_tasks();
        }
        ui.ctx().request_repaint_after(period);
        let mut selected = None;
        if self.workbench.review_tasks.is_empty() {
            ui.label("No review runs yet.");
        }
        egui::ScrollArea::vertical()
            .id_salt("jobs")
            .max_height(135.0)
            .show(ui, |ui| {
                for task in &self.workbench.review_tasks {
                    let label = format!(
                        "#{}   {:?}   ·   {} scanned   ·   {} findings",
                        task.task.id, task.task.state, task.counts.scanned, task.counts.findings
                    );
                    if ui
                        .selectable_label(
                            self.workbench.review_selection == Some(task.task.id),
                            label,
                        )
                        .clicked()
                    {
                        selected = Some(task.task.id);
                    }
                }
            });
        if let Some(selected) = selected {
            self.workbench.review_selection = Some(selected);
            self.workbench.task_offset = 0;
            self.refresh_tasks();
        }
        let task = self
            .workbench
            .review_tasks
            .iter()
            .find(|task| Some(task.task.id) == self.workbench.review_selection)
            .cloned();
        if let Some(task) = task {
            ui.separator();
            let active = matches!(task.task.state, TaskState::Pending | TaskState::Running);
            ui.label(
                RichText::new(format!("Review #{} · {:?}", task.task.id, task.task.state)).strong(),
            );
            ui.add(
                egui::ProgressBar::new(task.counts.examined as f32 / task.limit as f32).text(
                    format!(
                        "{} examined · {} matched · {} findings",
                        task.counts.examined, task.counts.scanned, task.counts.findings
                    ),
                ),
            );
            if let Some(workflow) = task.workflow {
                ui.label(format!("{} · Version {}", workflow.name, workflow.version));
            }
            if let Some(archive) = task.archive {
                let status = match archive.imported {
                    Some(imported) => {
                        let exchanges = if imported == 1 {
                            "exchange"
                        } else {
                            "exchanges"
                        };
                        let warnings = if archive.warning_count == 1 {
                            "warning"
                        } else {
                            "warnings"
                        };
                        let action = if archive.reused { "reused" } else { "imported" };
                        format!(
                            "{imported} {exchanges} {action} · {} {warnings}",
                            archive.warning_count
                        )
                    }
                    None if active => "Importing archive".into(),
                    None => "Import incomplete".into(),
                };
                ui.label(format!("{} · {status}", archive.name));
                if let Some(hash) = archive.sha256 {
                    ui.monospace(format!("SHA-256 {hash}"));
                }
                if !archive.warnings.is_empty() {
                    ui.collapsing("Import warnings", |ui| {
                        for warning in &archive.warnings {
                            ui.label(warning);
                        }
                    });
                }
            }
            if !task.query.is_empty() {
                ui.monospace(task.query);
            }
            if task.counts.skipped_large > 0 || task.counts.omitted > 0 {
                ui.label(format!(
                    "{} oversized exchanges skipped · {} candidates omitted",
                    task.counts.skipped_large, task.counts.omitted
                ));
            }
            if let Some(error) = task.error {
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
            if active && ui.button("Cancel review").clicked() {
                let result = self
                    .open()
                    .and_then(|s| s.cancel_review(task.task.id).map_err(message));
                if let Err(error) = result {
                    self.out = Output::Error(error);
                }
                self.refresh_tasks();
            }
            if !active {
                ui.horizontal_wrapped(|ui| {
                    self.report_menu(ui, Some(task.task.id));
                    if ui.button("Copy evidence bundle").clicked() {
                        let result = self.open().and_then(|store| {
                            let bundle = store.review_evidence_bundle(task.task.id).map_err(message)?;
                            serde_json::to_string_pretty(&bundle).map_err(message)
                        });
                        match result {
                            Ok(bundle) => { ui.ctx().copy_text(bundle); self.out = Output::Text("Evidence bundle copied.".into()); }
                            Err(error) => self.out = Output::Error(error),
                        }
                    }
                });
            }
            let mut offset = self.workbench.task_offset;
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(offset > 0, egui::Button::new("Previous results"))
                    .clicked()
                {
                    offset = offset.saturating_sub(50);
                }
                if ui
                    .add_enabled(
                        offset + 50 < task.counts.findings,
                        egui::Button::new("Next results"),
                    )
                    .clicked()
                {
                    offset += 50;
                }
            });
            if offset != self.workbench.task_offset {
                self.workbench.task_offset = offset;
                self.refresh_tasks();
            }
            if let Some(id) = task_result_ui(ui, &self.workbench.task_findings) {
                self.open_inspector(id);
            }
        }
    }

    fn refresh_findings(&mut self) {
        match self.open().and_then(|store| {
            store
                .finding_reviews(
                    self.workbench.review_filter,
                    self.workbench.finding_offset,
                    50,
                )
                .map_err(message)
        }) {
            Ok(findings) => self.workbench.findings = findings,
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn findings_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Findings");
        let previous = self.workbench.review_filter;
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("finding-status")
                .selected_text(previous.map_or("All statuses", ReviewState::as_str))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.workbench.review_filter, None, "All statuses");
                    for state in ReviewState::ALL {
                        ui.selectable_value(
                            &mut self.workbench.review_filter,
                            Some(state),
                            state.as_str(),
                        );
                    }
                });
            if ui.button("Refresh").clicked() {
                self.refresh_findings();
            }
            self.report_menu(ui, None);
        });
        if previous != self.workbench.review_filter {
            self.workbench.finding_offset = 0;
            self.refresh_findings();
        }
        let mut update = None;
        if let Some((id, state, note)) = self.workbench.finding_draft.as_mut() {
            ui.separator();
            ui.label(RichText::new(format!("Triage finding #{id}")).strong());
            egui::ComboBox::from_id_salt("draft-state")
                .selected_text(state.as_str())
                .show_ui(ui, |ui| {
                    for option in ReviewState::ALL {
                        ui.selectable_value(state, option, option.as_str());
                    }
                });
            ui.add(
                egui::TextEdit::multiline(note)
                    .hint_text("Review notes")
                    .desired_width(f32::INFINITY),
            );
            ui.horizontal(|ui| {
                if ui.button("Save triage").clicked() {
                    update = Some(Some((*id, *state, note.clone())));
                }
                if ui.button("Close").clicked() {
                    update = Some(None);
                }
            });
        }
        match update {
            Some(Some((id, state, note))) => {
                let result = self.open().and_then(|store| {
                    store
                        .update_finding_review(id, state, &note)
                        .map_err(message)
                });
                if result.is_ok() {
                    self.refresh_findings();
                }
                self.operation(result, "Triage saved.");
            }
            Some(None) => self.workbench.finding_draft = None,
            None => {}
        }
        let mut draft = None;
        let mut inspect = None;
        if self.workbench.findings.is_empty() {
            ui.label("No findings on this page.");
        }
        for review in &self.workbench.findings {
            ui.push_id(review.finding.id.0, |ui| {
                ui.collapsing(
                    format!(
                        "{:?} · {} · {}",
                        review.finding.severity,
                        review.state.as_str(),
                        review.finding.title
                    ),
                    |ui| {
                        ui.label(&review.finding.detail);
                        if !review.note.is_empty() {
                            ui.label(&review.note);
                        }
                        if let Some(id) = evidence_buttons(ui, &review.finding) {
                            inspect = Some(id);
                        }
                        if ui.button("Triage finding").clicked() {
                            draft = Some((review.finding.id, review.state, review.note.clone()));
                        }
                    },
                );
            });
        }
        if let Some(draft) = draft {
            self.workbench.finding_draft = Some(draft);
        }
        if let Some(id) = inspect {
            self.open_inspector(id);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.workbench.finding_offset > 0,
                    egui::Button::new("Previous"),
                )
                .clicked()
            {
                self.workbench.finding_offset = self.workbench.finding_offset.saturating_sub(50);
                self.refresh_findings();
            }
            if ui
                .add_enabled(
                    self.workbench.findings.len() == 50,
                    egui::Button::new("Next"),
                )
                .clicked()
            {
                self.workbench.finding_offset += 50;
                self.refresh_findings();
            }
        });
    }

    fn report_menu(&mut self, ui: &mut egui::Ui, task: Option<TaskId>) {
        ui.menu_button(
            if task.is_some() {
                "Copy run report"
            } else {
                "Copy redacted report"
            },
            |ui| {
                for format in ReportFormat::ALL {
                    if ui.button(format.label()).clicked() {
                        let result = self.open().and_then(|store| {
                            let report = match task {
                                Some(id) => store.review_report(id),
                                None => store.finding_report(self.workbench.review_filter),
                            };
                            report
                                .and_then(|report| report.render(format))
                                .map_err(message)
                        });
                        match result {
                            Ok(text) => {
                                ui.ctx().copy_text(text);
                                self.out =
                                    Output::Text(format!("{} report copied.", format.label()));
                            }
                            Err(error) => self.out = Output::Error(error),
                        }
                        ui.close_menu();
                    }
                }
            },
        );
    }

    fn refresh_artifacts(&mut self) {
        match self.open().and_then(|store| {
            store
                .artifacts(self.workbench.artifact_before)
                .map_err(message)
        }) {
            Ok(artifacts) => self.workbench.artifacts = artifacts,
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn integrations_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Integration evidence");
        ui.label("Import existing httpx or Nuclei JSONL. Other reports can be stored as raw text.");
        egui::ComboBox::from_id_salt("artifact-format")
            .selected_text(self.workbench.artifact_format.label())
            .show_ui(ui, |ui| {
                for format in ArtifactFormat::ALL {
                    ui.selectable_value(
                        &mut self.workbench.artifact_format,
                        format,
                        format.label(),
                    );
                }
            });
        ui.horizontal_wrapped(|ui| {
            ui.label("File path");
            ui.add(
                egui::TextEdit::singleline(&mut self.workbench.artifact_path).desired_width(230.0),
            );
            ui.label("Tool version (optional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.workbench.artifact_version)
                    .desired_width(100.0),
            );
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.workbench.artifact_text)
                .hint_text("Or paste evidence")
                .desired_width(f32::INFINITY)
                .desired_rows(4),
        );
        ui.horizontal_wrapped(|ui| {
            for (label, save) in [("Preview evidence", false), ("Store evidence", true)] {
                if ui.button(label).clicked() {
                    self.import_evidence(save);
                }
            }
            if ui.button("Refresh").clicked() {
                self.refresh_artifacts();
            }
        });
        ui.separator();
        ui.heading("Stored artifacts");
        if self.workbench.artifacts.is_empty() {
            ui.label("No artifacts on this page.");
        }
        let mut selected = None;
        egui::ScrollArea::vertical()
            .id_salt("artifact-list")
            .max_height(150.0)
            .show(ui, |ui| {
                for item in &self.workbench.artifacts {
                    let label = format!(
                        "#{}   {}   ·   {} records   ·   {} skipped",
                        item.id, item.format, item.records, item.skipped
                    );
                    if ui
                        .selectable_label(Some(item.id) == self.workbench.artifact_selected, label)
                        .clicked()
                    {
                        selected = Some(item.id);
                    }
                }
            });
        ui.horizontal_wrapped(|ui| {
            if self.workbench.artifact_before.is_some() && ui.button("Newest artifacts").clicked() {
                self.workbench.artifact_before = None;
                self.refresh_artifacts();
            }
            if self.workbench.artifacts.len() == 50 && ui.button("Older artifacts").clicked() {
                self.workbench.artifact_before =
                    self.workbench.artifacts.last().map(|artifact| artifact.id);
                self.refresh_artifacts();
            }
        });
        if let Some(id) = selected {
            self.workbench.artifact_selected = Some(id);
            self.workbench.artifact_cursor = None;
            self.read_observations(id);
        }
        if let Some(id) = self.workbench.artifact_selected {
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!("Artifact #{id}")).strong());
                if ui.button("Copy original text").clicked() {
                    let result = self
                        .open()
                        .and_then(|store| store.artifact_text(id).map_err(message))
                        .and_then(|raw| raw.ok_or_else(|| "Artifact was not found.".into()));
                    match result {
                        Ok(raw) => {
                            ui.ctx().copy_text(raw);
                            self.out = Output::Text("Original evidence copied.".into());
                        }
                        Err(error) => self.out = Output::Error(error),
                    }
                }
                if self.workbench.artifact_cursor.is_some()
                    && ui.button("Newest observations").clicked()
                {
                    self.workbench.artifact_cursor = None;
                    self.read_observations(id);
                }
                if self.workbench.artifact_next.is_some()
                    && ui.button("Older observations").clicked()
                {
                    self.workbench.artifact_cursor = self.workbench.artifact_next;
                    self.read_observations(id);
                }
            });
            for observation in &self.workbench.artifact_rows {
                ui.push_id(observation.line, |ui| {
                    ui.collapsing(
                        format!(
                            "Line {} · {} · {}",
                            observation.line, observation.outcome, observation.location
                        ),
                        |ui| {
                            if let Some(title) = &observation.title {
                                ui.label(title);
                            }
                            for (label, value) in [
                                ("Template", observation.template.as_deref()),
                                ("Matcher", observation.matcher.as_deref()),
                                ("Severity", observation.severity.as_deref()),
                                ("Server", observation.server.as_deref()),
                                ("Content type", observation.content_type.as_deref()),
                                ("Timestamp", observation.timestamp.as_deref()),
                            ] {
                                if let Some(value) = value {
                                    ui.label(format!("{label}  {value}"));
                                }
                            }
                            if let Some(status) = observation.status {
                                ui.label(format!("HTTP {status}"));
                            }
                            if !observation.technologies.is_empty() {
                                ui.label(observation.technologies.join(", "));
                            }
                        },
                    );
                });
            }
        }
    }

    pub(super) fn open_inventory_artifact(&mut self, id: i64) {
        self.navigate(Surface::Integrations);
        self.workbench.artifact_selected = Some(id);
        self.workbench.artifact_cursor = None;
        self.read_observations(id);
    }

    fn read_observations(&mut self, id: i64) {
        match self.open().and_then(|store| {
            store
                .observations(id, self.workbench.artifact_cursor)
                .map_err(message)
        }) {
            Ok(page) => {
                self.workbench.artifact_next = page.next_before;
                self.workbench.artifact_rows = page.observations;
            }
            Err(error) => self.out = Output::Error(error),
        }
    }

    fn import_evidence(&mut self, save: bool) {
        let result = (|| {
            let data = local_input(&self.workbench.artifact_path, &self.workbench.artifact_text)?;
            let content = std::str::from_utf8(&data).map_err(message)?;
            self.open()?
                .import_artifact(
                    self.workbench.artifact_format,
                    content,
                    Some(&self.workbench.artifact_version),
                    save,
                )
                .map_err(message)
        })();
        match result {
            Ok(result) => {
                self.out = Output::Text(format!(
                    "{} records · {} skipped{}\nSHA-256 {}\n{}",
                    result.records,
                    result.skipped,
                    result
                        .artifact_id
                        .map(|id| format!(" · Artifact #{id}"))
                        .unwrap_or_default(),
                    result.sha256,
                    result.warnings.join("\n")
                ));
                if let Some(id) = result.artifact_id {
                    self.workbench.artifact_before = None;
                    self.refresh_artifacts();
                    self.workbench.artifact_selected = Some(id);
                    self.workbench.artifact_cursor = None;
                    self.read_observations(id);
                } else {
                    let preview = result
                        .sample
                        .iter()
                        .map(|row| {
                            format!("Line {} • {} • {}", row.line, row.outcome, row.location)
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    if let Output::Text(text) = &mut self.out {
                        text.push('\n');
                        text.push_str(&preview);
                    }
                }
            }
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn library_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Library");
        ui.label("Return to saved exchanges and CamioQL searches.");
        ui.separator();
        ui.heading("Saved exchanges");
        let entries = &self.workbench.saved_exchanges;
        let has_next = entries.len() == 100;
        if entries.is_empty() {
            ui.label("Save an exchange from its inspector to see it here.");
        }
        let mut selected_exchange = None;
        for entry in entries {
            ui.horizontal_wrapped(|ui| {
                if ui.link(format!("#{}", entry.id)).clicked() {
                    selected_exchange = Some(entry.id);
                }
                ui.label(&entry.label);
                ui.monospace(&entry.url);
                if !entry.note.is_empty() {
                    ui.label(&entry.note);
                }
            });
        }
        if let Some(id) = selected_exchange {
            self.open_inspector(id);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.workbench.library_offset > 0,
                    egui::Button::new("Previous"),
                )
                .clicked()
            {
                self.workbench.library_offset = self.workbench.library_offset.saturating_sub(100);
                self.reload_saved_exchanges();
            }
            if ui
                .add_enabled(has_next, egui::Button::new("Next"))
                .clicked()
            {
                self.workbench.library_offset += 100;
                self.reload_saved_exchanges();
            }
            if ui.button("Refresh library").clicked() {
                self.reload_saved_exchanges();
                self.reload_queries();
            }
        });

        ui.separator();
        ui.heading("Saved queries");
        let mut remove = None;
        let mut selected = None;
        for query in &self.workbench.saved_queries {
            ui.horizontal_wrapped(|ui| {
                ui.label(&query.name);
                ui.monospace(&query.expression);
                if ui.button("Run").clicked() {
                    selected = Some(query.expression.clone());
                }
                if ui.button("Remove").clicked() {
                    remove = Some(query.name.clone());
                }
            });
        }
        if self.workbench.saved_queries.is_empty() {
            ui.label("Save a filter in History or CamioQL to reuse it here.");
        }
        if let Some(name) = remove {
            let result = self
                .open()
                .and_then(|store| store.delete_query(&name).map_err(message));
            if result.is_ok() {
                self.reload_queries();
            }
            self.operation(result, "Saved query removed.");
        }
        if let Some(query) = selected {
            self.query = query;
            self.navigate(Surface::Query);
            self.refresh_history(true);
        }
    }

    pub(super) fn workspace_settings(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Workspace name");
            ui.add(
                egui::TextEdit::singleline(&mut self.workbench.workspace_name).desired_width(215.0),
            );
            if ui.button("Save name").clicked() {
                let result = self.open().and_then(|store| {
                    store
                        .rename_workspace(&self.workbench.workspace_name)
                        .map_err(message)
                });
                if result.is_ok() {
                    self.refresh_overview();
                }
                self.operation(result, "Workspace name saved.");
            }
        });
    }

    fn operation(&mut self, result: Result<(), String>, notice: &str) {
        self.out = match result {
            Ok(()) => Output::Text(notice.into()),
            Err(error) => Output::Error(error),
        }
    }

    pub(super) fn workbench_notice(&self, ui: &mut egui::Ui) {
        match &self.out {
            Output::Text(text) => {
                ui.separator();
                ui.label(text);
            }
            Output::Error(error) => {
                ui.separator();
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
            _ => {}
        }
    }
}

fn history_rows(
    ui: &mut egui::Ui,
    rows: &[camio_store::HistoryRow],
    height: f32,
    salt: &str,
) -> Option<ExchangeId> {
    if rows.is_empty() {
        return None;
    }
    let mut clicked = None;
    egui::ScrollArea::vertical()
        .id_salt(salt)
        .max_height(height)
        .auto_shrink([false, true])
        .show_rows(ui, 24.0, rows.len(), |ui, range| {
            for index in range {
                let row = &rows[index];
                ui.push_id(row.id.0, |ui| {
                    ui.horizontal(|ui| {
                        if ui.link(format!("#{}", row.id)).clicked() {
                            clicked = Some(row.id);
                        }
                        let method =
                            egui::Label::new(RichText::new(&row.method).monospace()).truncate();
                        ui.add_sized([50.0, 24.0], method);
                        ui.add_sized(
                            [35.0, 24.0],
                            egui::Label::new(
                                row.status
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| "—".into()),
                            ),
                        );
                        ui.add(egui::Label::new(RichText::new(&row.url).monospace()).truncate())
                            .on_hover_text(&row.url);
                    });
                });
            }
        });
    clicked
}

fn message_view(ui: &mut egui::Ui, inspector: &Inspector) {
    let exchange = &inspector.preview.exchange;
    let (start, headers, body, length) = if inspector.response {
        let Some(response) = exchange.response.as_ref() else {
            return;
        };
        (
            format!(
                "{} {} {}",
                response.version.wire_token(),
                response.status,
                response.reason.as_deref().unwrap_or_default()
            ),
            &response.headers,
            &response.body,
            inspector.preview.resp_len.unwrap_or(0),
        )
    } else {
        let request = &exchange.request;
        (
            format!(
                "{} {} {}",
                request.method,
                request.url,
                request.version.wire_token()
            ),
            &request.headers,
            &request.body,
            inspector.preview.req_len,
        )
    };
    ui.label(if body.len() as i64 >= length {
        format!("{length} bytes")
    } else {
        format!("Showing {} of {length} bytes", body.len())
    });
    egui::ScrollArea::both()
        .id_salt("exchange-bytes")
        .max_height(290.0)
        .auto_shrink([false, true])
        .show(ui, |ui| match inspector.view {
            MessageView::Structured => {
                ui.monospace(start);
                egui::Grid::new("exchange-headers")
                    .striped(true)
                    .num_columns(2)
                    .show(ui, |ui| {
                        for header in headers.iter() {
                            ui.monospace(&header.name);
                            ui.monospace(&header.value);
                            ui.end_row();
                        }
                    });
                ui.monospace(if body.is_empty() {
                    "(empty body)".into()
                } else {
                    body.as_text()
                });
            }
            MessageView::Raw => {
                ui.label("Reconstructed message");
                ui.monospace(format!(
                    "{start}\r\n{}\r\n{}",
                    headers
                        .iter()
                        .map(|header| format!("{}: {}\r\n", header.name, header.value))
                        .collect::<String>(),
                    body.as_text()
                ));
            }
            MessageView::Hex => {
                use std::fmt::Write;
                let mut text = String::new();
                for (index, chunk) in body.as_bytes().chunks(16).enumerate() {
                    let _ = write!(text, "{:06x}  ", index * 16);
                    for byte in chunk {
                        let _ = write!(text, "{byte:02x} ");
                    }
                    text.push('\n');
                }
                ui.monospace(if text.is_empty() {
                    "(empty body)".into()
                } else {
                    text
                });
            }
        });
}

fn task_result_ui(ui: &mut egui::Ui, findings: &[Finding]) -> Option<ExchangeId> {
    let mut inspect = None;
    for (index, finding) in findings.iter().enumerate() {
        ui.push_id(index, |ui| {
            ui.collapsing(
                format!("{:?} · {}", finding.severity, finding.title),
                |ui| {
                    ui.label(&finding.detail);
                    if let Some(id) = evidence_buttons(ui, finding) {
                        inspect = Some(id);
                    }
                },
            );
        });
    }
    inspect
}

fn evidence_buttons(ui: &mut egui::Ui, finding: &Finding) -> Option<ExchangeId> {
    let mut inspect = None;
    ui.horizontal_wrapped(|ui| {
        for id in &finding.evidence {
            if ui.link(format!("Exchange #{id}")).clicked() {
                inspect = Some(*id);
            }
        }
    });
    inspect
}

pub(super) fn local_input(path: &str, contents: &str) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    if !path.trim().is_empty() {
        let path = path.trim();
        if !std::fs::metadata(path).map_err(message)?.is_file() {
            return Err("Select a regular file.".into());
        }
        std::fs::File::open(path)
            .map_err(message)?
            .take(ARTIFACT_BYTES as u64 + 1)
            .read_to_end(&mut data)
            .map_err(message)?;
    } else if contents.len() <= ARTIFACT_BYTES {
        data.extend_from_slice(contents.as_bytes());
    } else {
        return Err("Select up to 4 MiB of content.".into());
    }
    if data.len() > ARTIFACT_BYTES {
        return Err("Select up to 4 MiB of content.".into());
    }
    if data.is_empty() {
        return Err("Choose a file or paste its contents.".into());
    }
    Ok(data)
}

fn message(error: impl ToString) -> String {
    error.to_string()
}

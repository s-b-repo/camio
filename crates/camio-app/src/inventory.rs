use super::{CamioApp, Output};
use camio_core::ExchangeId;
use camio_store::{AssetInventory, EndpointEvidence, InventoryPage};
use egui::{RichText, Stroke};

#[derive(Default)]
pub(super) struct InventoryPane {
    filter: String,
    applied_filter: String,
    page: Option<InventoryPage>,
    cursors: Vec<String>,
    asset: Option<AssetInventory>,
    endpoint_after: Option<String>,
    label: String,
    note: String,
    evidence: Option<EndpointEvidence>,
    evidence_before: Option<i64>,
}

impl CamioApp {
    pub(super) fn refresh_inventory(&mut self) {
        match self.open().and_then(|store| store.inventory(
            &self.inventory.applied_filter,
            self.inventory.cursors.last().map(String::as_str),
        ).map_err(message)) {
            Ok(page) => self.inventory.page = Some(page),
            Err(error) => self.out = Output::Error(error),
        }
    }

    fn load_asset(&mut self, origin: &str, reset: bool) {
        if reset {
            self.inventory.endpoint_after = None;
            self.inventory.evidence = None;
            self.inventory.evidence_before = None;
        }
        match self.open().and_then(|store| store.asset_inventory(origin, self.inventory.endpoint_after.as_deref()).map_err(message)) {
            Ok(asset) => {
                if reset {
                    self.inventory.label.clone_from(&asset.note.label);
                    self.inventory.note.clone_from(&asset.note.note);
                }
                self.inventory.asset = Some(asset);
            }
            Err(error) => self.out = Output::Error(error),
        }
    }

    fn load_endpoint(&mut self, endpoint: &str) {
        match self.open().and_then(|store| store.endpoint_evidence(endpoint, self.inventory.evidence_before).map_err(message)) {
            Ok(evidence) => self.inventory.evidence = Some(evidence),
            Err(error) => self.out = Output::Error(error),
        }
    }

    pub(super) fn inventory_ui(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(self.theme.panel_color())
            .rounding(self.theme.rounding)
            .stroke(Stroke::new(1.0_f32, self.theme.accent_color().gamma_multiply(0.55)))
            .inner_margin(egui::Margin::same(13.0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.heading("Asset inventory");
                ui.label("Captured traffic and imported observations grouped by origin.");
            });
        ui.horizontal_wrapped(|ui| {
            let input = ui.add(egui::TextEdit::singleline(&mut self.inventory.filter)
                .hint_text("Filter origins").desired_width(240.0).char_limit(256));
            if ui.button("Filter").clicked() || (input.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter))) {
                self.inventory.applied_filter = self.inventory.filter.trim().to_owned();
                self.inventory.cursors.clear();
                self.refresh_inventory();
            }
            if ui.button("Refresh").clicked() { self.refresh_inventory(); }
        });

        let mut origin = None;
        if let Some(page) = &self.inventory.page {
            if page.assets.is_empty() { ui.label("No recorded assets on this page."); }
            else {
                egui::ScrollArea::vertical().id_salt("recorded-assets").max_height(220.0).show(ui, |ui| {
                    egui::Grid::new("asset-origins").striped(true).show(ui, |ui| {
                        for column in ["Origin", "Endpoints", "Captured", "httpx", "Nuclei"] { ui.strong(column); }
                        ui.end_row();
                        for asset in &page.assets {
                            let row = ui.add(egui::Label::new(RichText::new(&asset.origin).monospace().color(self.theme.accent_color()))
                                .truncate().sense(egui::Sense::click()));
                            if row.on_hover_text(if asset.label.is_empty() { &asset.origin } else { &asset.label }).clicked() {
                                origin = Some(asset.origin.clone());
                            }
                            ui.label(asset.endpoints.to_string()); ui.label(asset.captured.to_string());
                            ui.label(asset.httpx.to_string()); ui.label(asset.nuclei.to_string());
                            ui.end_row();
                        }
                    });
                });
            }
            let next = page.next_after.clone();
            ui.horizontal(|ui| {
                if !self.inventory.cursors.is_empty() && ui.button("Previous origins").clicked() {
                    self.inventory.cursors.pop();
                    self.refresh_inventory();
                }
                if let Some(next) = next {
                    if ui.button("More origins").clicked() {
                        self.inventory.cursors.push(next);
                        self.refresh_inventory();
                    }
                }
            });
        }
        if let Some(origin) = origin { self.load_asset(&origin, true); }
        self.asset_inventory_ui(ui);
        self.endpoint_evidence_ui(ui);
    }

    fn asset_inventory_ui(&mut self, ui: &mut egui::Ui) {
        let Some(asset) = self.inventory.asset.as_ref() else { return; };
        let origin = asset.asset.origin.clone();
        let next = asset.next_after.clone();
        let mut endpoint = None;
        ui.separator();
        ui.heading("Endpoints");
        ui.monospace(&origin);
        egui::ScrollArea::vertical().id_salt("asset-endpoints").max_height(190.0).show(ui, |ui| {
            for item in &asset.endpoints {
                ui.horizontal_wrapped(|ui| {
                    if ui.link(RichText::new(&item.location).monospace()).clicked() {
                        endpoint = Some(item.location.clone());
                    }
                    ui.label(format!("{} captured · {} httpx · {} Nuclei", item.captured, item.httpx, item.nuclei));
                });
            }
        });
        ui.horizontal(|ui| {
            if self.inventory.endpoint_after.is_some() && ui.button("First endpoints").clicked() {
                self.inventory.endpoint_after = None;
                self.load_asset(&origin, false);
            }
            if let Some(next) = next {
                if ui.button("More endpoints").clicked() {
                    self.inventory.endpoint_after = Some(next);
                    self.load_asset(&origin, false);
                }
            }
        });
        ui.collapsing("Asset notes", |ui| {
            ui.label("Label");
            ui.text_edit_singleline(&mut self.inventory.label);
            ui.label("Note");
            ui.add(egui::TextEdit::multiline(&mut self.inventory.note).desired_width(f32::INFINITY).desired_rows(3));
            if ui.button("Save asset note").clicked() {
                let result = self.open().and_then(|store| store.save_asset_note(&origin, &self.inventory.label, &self.inventory.note).map_err(message));
                match result {
                    Ok(()) => {
                        self.out = Output::Text("Asset note saved.".into());
                        self.refresh_inventory();
                    }
                    Err(error) => self.out = Output::Error(error),
                }
            }
        });
        if let Some(endpoint) = endpoint {
            self.inventory.evidence_before = None;
            self.load_endpoint(&endpoint);
        }
    }

    fn endpoint_evidence_ui(&mut self, ui: &mut egui::Ui) {
        let Some(evidence) = self.inventory.evidence.as_ref() else { return; };
        let location = evidence.location.clone();
        let next = evidence.next_before;
        let mut record = None;
        ui.separator();
        ui.heading("Endpoint evidence");
        ui.monospace(&location);
        egui::ScrollArea::vertical().id_salt("asset-evidence").max_height(230.0).show(ui, |ui| {
            for item in &evidence.records {
                ui.horizontal_wrapped(|ui| {
                    if let Some(id) = item.exchange_id {
                        if ui.link(format!("Exchange #{id}")).clicked() { record = Some(EvidenceLink::Exchange(id)); }
                    } else if let Some(id) = item.artifact_id {
                        if ui.link(format!("Artifact #{id} · Line {}", item.line.unwrap_or_default())).clicked() {
                            record = Some(EvidenceLink::Artifact(id));
                        }
                    }
                    ui.label(&item.source);
                    if let Some(status) = item.status { ui.monospace(status.to_string()); }
                    if let Some(outcome) = &item.outcome { ui.label(outcome); }
                    if let Some(label) = &item.description { ui.label(label); }
                });
            }
            if evidence.records.is_empty() { ui.label("No evidence on this page."); }
        });
        ui.horizontal(|ui| {
            if self.inventory.evidence_before.is_some() && ui.button("Newest evidence").clicked() {
                self.inventory.evidence_before = None;
                self.load_endpoint(&location);
            }
            if let Some(next) = next {
                if ui.button("Older evidence").clicked() {
                    self.inventory.evidence_before = Some(next);
                    self.load_endpoint(&location);
                }
            }
        });
        match record {
            Some(EvidenceLink::Exchange(id)) => self.open_inspector(id),
            Some(EvidenceLink::Artifact(id)) => self.open_inventory_artifact(id),
            None => {}
        }
    }
}

enum EvidenceLink { Exchange(ExchangeId), Artifact(i64) }

fn message(error: impl ToString) -> String { error.to_string() }

//! Theme system for the native app (plan §7.1: "Native light/dark + themes,
//! WCAG 2.1 AA … high-contrast option").
//!
//! A [`Theme`] is a small, serializable description of colours, corner rounding,
//! and an optional background image. It is applied to egui's [`egui::Visuals`]
//! every frame (so edits in the Settings surface take effect live) and persisted
//! to a JSON file so it survives restarts. Several presets ship, including an
//! "Antigravity" accent and a "LibreWolf" palette.

use egui::{Color32, Rounding, Stroke, Visuals};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A customizable theme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Theme {
    pub name: String,
    pub dark: bool,
    /// Accent / selection colour (sRGB).
    pub accent: [u8; 3],
    /// Window (outer) fill.
    pub window: [u8; 3],
    /// Panel fill.
    pub panel: [u8; 3],
    /// Primary text colour.
    pub text: [u8; 3],
    /// Widget corner rounding, in points.
    pub rounding: f32,
    /// Optional background image path.
    #[serde(default)]
    pub bg_image: Option<PathBuf>,
    /// Background image opacity, `0.0..=1.0`.
    #[serde(default = "default_opacity")]
    pub bg_opacity: f32,
}

fn default_opacity() -> f32 {
    0.18
}

impl Default for Theme {
    fn default() -> Self {
        Self::presets()
            .into_iter()
            .next()
            .expect("at least one preset")
    }
}

impl Theme {
    /// The built-in theme presets.
    pub fn presets() -> Vec<Theme> {
        vec![
            Theme {
                name: "Midnight".into(),
                dark: true,
                accent: [88, 166, 255],
                window: [13, 17, 23],
                panel: [22, 27, 34],
                text: [217, 222, 229],
                rounding: 6.0,
                bg_image: None,
                bg_opacity: 0.18,
            },
            Theme {
                name: "Antigravity".into(),
                dark: true,
                accent: [139, 124, 248],
                window: [11, 12, 20],
                panel: [20, 20, 34],
                text: [226, 224, 244],
                rounding: 10.0,
                bg_image: None,
                bg_opacity: 0.22,
            },
            Theme {
                name: "LibreWolf".into(),
                dark: true,
                accent: [255, 160, 70],
                window: [18, 16, 20],
                panel: [28, 24, 30],
                text: [232, 226, 220],
                rounding: 7.0,
                bg_image: None,
                bg_opacity: 0.18,
            },
            Theme {
                name: "Carbon".into(),
                dark: true,
                accent: [120, 220, 170],
                window: [16, 16, 16],
                panel: [26, 26, 26],
                text: [224, 224, 224],
                rounding: 4.0,
                bg_image: None,
                bg_opacity: 0.15,
            },
            Theme {
                name: "Matrix".into(),
                dark: true,
                accent: [80, 240, 120],
                window: [6, 12, 8],
                panel: [12, 22, 14],
                text: [180, 240, 190],
                rounding: 3.0,
                bg_image: None,
                bg_opacity: 0.2,
            },
            Theme {
                name: "Daylight".into(),
                dark: false,
                accent: [31, 111, 235],
                window: [246, 248, 250],
                panel: [255, 255, 255],
                text: [26, 30, 36],
                rounding: 6.0,
                bg_image: None,
                bg_opacity: 0.1,
            },
            Theme {
                name: "High Contrast".into(),
                dark: true,
                accent: [255, 221, 0],
                window: [0, 0, 0],
                panel: [10, 10, 10],
                text: [255, 255, 255],
                rounding: 2.0,
                bg_image: None,
                bg_opacity: 0.0,
            },
        ]
    }

    /// Apply this theme to the egui context.
    pub fn apply(&self, ctx: &egui::Context) {
        let mut v = if self.dark {
            Visuals::dark()
        } else {
            Visuals::light()
        };
        let accent = col(self.accent);

        v.hyperlink_color = accent;
        v.selection.bg_fill = accent.gamma_multiply(0.45);
        v.selection.stroke = Stroke::new(1.0_f32, accent);

        v.widgets.hovered.weak_bg_fill = accent.gamma_multiply(0.22);
        v.widgets.hovered.bg_fill = accent.gamma_multiply(0.30);
        v.widgets.active.weak_bg_fill = accent.gamma_multiply(0.55);
        v.widgets.active.bg_fill = accent.gamma_multiply(0.75);

        v.window_fill = col(self.window);
        v.panel_fill = col(self.panel);
        v.extreme_bg_color = col(scale(self.window, 0.6));
        v.override_text_color = Some(col(self.text));

        let r = Rounding::same(self.rounding);
        v.window_rounding = r;
        v.menu_rounding = r;
        v.widgets.noninteractive.rounding = r;
        v.widgets.inactive.rounding = r;
        v.widgets.hovered.rounding = r;
        v.widgets.active.rounding = r;
        v.widgets.open.rounding = r;

        ctx.set_visuals(v);
    }
}

fn col([r, g, b]: [u8; 3]) -> Color32 {
    Color32::from_rgb(r, g, b)
}

fn scale([r, g, b]: [u8; 3], f: f32) -> [u8; 3] {
    [
        (r as f32 * f) as u8,
        (g as f32 * f) as u8,
        (b as f32 * f) as u8,
    ]
}

/// Where the theme config is stored (`$HOME/.config/camio/theme.json`, or
/// `./camio-theme.json` when `$HOME` is unavailable).
pub fn config_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join(".config")
            .join("camio")
            .join("theme.json")
    } else {
        PathBuf::from("camio-theme.json")
    }
}

/// Load the saved theme, or the default preset if none/unreadable.
pub fn load() -> Theme {
    let path = config_path();
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<Theme>(&s).ok())
        .unwrap_or_default()
}

/// Persist a theme to the config path, creating the directory if needed.
pub fn save(theme: &Theme) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating config dir: {e}"))?;
    }
    let json = serde_json::to_string_pretty(theme).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Decode an image file into an egui texture for use as a background.
pub fn load_texture(ctx: &egui::Context, path: &Path) -> Result<egui::TextureHandle, String> {
    let img = image::open(path).map_err(|e| format!("loading image: {e}"))?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let color = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], rgba.as_raw());
    Ok(ctx.load_texture("camio_bg", color, egui::TextureOptions::LINEAR))
}

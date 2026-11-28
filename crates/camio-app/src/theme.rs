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
    /// Animate the overview and interface transitions.
    #[serde(default = "motion_enabled")]
    pub motion: bool,
}

fn default_opacity() -> f32 {
    0.18
}

fn motion_enabled() -> bool {
    true
}

impl Default for Theme {
    fn default() -> Self {
        // A built-in list, not data that can be empty — but if it ever were,
        // the first `unwrap_or` fallback keeps the UI bootable instead of
        // panicking before a single frame is drawn.
        Self::presets()
            .into_iter()
            .next()
            .unwrap_or_else(Theme::fallback)
    }
}

impl Theme {
    /// A hard-coded single theme, used only if the preset list above is ever
    /// emptied. Constructed here so `Default` never has to panic.
    fn fallback() -> Theme {
        Theme {
            name: "Camio".into(),
            dark: true,
            // Cyber Sec "Sentinel Blue": navy ink, sky-blue accent, blue-white
            // text — the exact palette from cybersec.org.za's styles.css.
            accent: [131, 188, 255],
            window: [8, 17, 31],
            panel: [16, 28, 47],
            text: [231, 238, 251],
            rounding: 14.0,
            bg_image: None,
            bg_opacity: 0.18,
            motion: true,
        }
    }

    /// The built-in theme presets.
    pub fn presets() -> Vec<Theme> {
        vec![
            Theme {
                // Cyber Sec's house palette (cybersec.org.za → styles.css):
                // navy ink #08111f, sky-blue accent #83bcff, blue-white text.
                name: "Sentinel Blue".into(),
                dark: true,
                accent: [131, 188, 255],
                window: [8, 17, 31],
                panel: [16, 28, 47],
                text: [231, 238, 251],
                rounding: 14.0,
                bg_image: None,
                bg_opacity: 0.18,
                motion: true,
            },
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
                motion: true,
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
                motion: true,
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
                motion: true,
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
                motion: true,
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
                motion: true,
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
                motion: true,
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
                motion: false,
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
        let accent = self.accent_color();

        v.hyperlink_color = accent;
        v.selection.bg_fill = accent.gamma_multiply(0.45);
        v.selection.stroke = Stroke::new(1.0_f32, accent);

        v.widgets.hovered.weak_bg_fill = accent.gamma_multiply(0.22);
        v.widgets.hovered.bg_fill = accent.gamma_multiply(0.30);
        v.widgets.active.weak_bg_fill = accent.gamma_multiply(0.55);
        v.widgets.active.bg_fill = accent.gamma_multiply(0.75);
        v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, accent);
        v.widgets.active.bg_stroke = Stroke::new(1.5_f32, accent);

        v.window_fill = col(self.window);
        v.panel_fill = col(self.panel);
        v.extreme_bg_color = col(scale(self.window, 0.6));
        v.override_text_color = Some(col(self.text));
        if self.name == "Sentinel Blue" {
            // Cyber Sec's navy surfaces with visibly *blue* controls: idle
            // widgets carry a sky-blue fill derived from the accent (#83bcff),
            // brightening on hover/active. Borders/surfaces use the site's
            // --line (#3b5877), --line-soft (#263a54) and --surface-2 (#17263c).
            v.widgets.noninteractive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(38, 58, 84)); // --line-soft
            v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, accent.gamma_multiply(0.7));
            v.widgets.inactive.weak_bg_fill = accent.gamma_multiply(0.18);
            v.widgets.inactive.bg_fill = accent.gamma_multiply(0.28);
            v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(231, 238, 251)); // --text
            v.extreme_bg_color = Color32::from_rgb(11, 20, 35); // --ink-2
            v.faint_bg_color = Color32::from_rgb(23, 38, 60); // --surface-2
            v.window_stroke = Stroke::new(1.0_f32, Color32::from_rgb(59, 88, 119)); // --line
        }

        let r = Rounding::same(self.rounding);
        v.window_rounding = r;
        v.menu_rounding = r;
        v.widgets.noninteractive.rounding = r;
        v.widgets.inactive.rounding = r;
        v.widgets.hovered.rounding = r;
        v.widgets.active.rounding = r;
        v.widgets.open.rounding = r;

        ctx.style_mut(|style| {
            style.visuals = v;
            style.animation_time = if self.motion { 0.16 } else { 0.0 };
            style.spacing.item_spacing = egui::vec2(9.0, 6.0);
            style.spacing.button_padding = egui::vec2(9.0, 4.0);
        });
    }

    pub fn accent_color(&self) -> Color32 {
        col(self.accent)
    }

    pub fn panel_color(&self) -> Color32 {
        col(self.panel)
    }

    pub fn window_color(&self) -> Color32 {
        col(self.window)
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

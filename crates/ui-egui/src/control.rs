//! The UI control channel (M3.9): lets an agent see and drive the running app.
//!
//! **Opt-in only.** Nothing here runs unless the app is started with `--control <file>` (or a
//! test attaches a [`ControlClient`]). The transport ([`serve`]) listens on loopback only, on a
//! random port, and every connection must first present the random token written to `<file>`.
//!
//! How it works:
//! - [`ControlPlugin`], an egui plugin, keeps a copy of the AccessKit tree from every frame's
//!   output (the widget tree with ids, roles, labels, rects and states) and injects queued input
//!   events (AccessKit click actions, pointer events, keys, text) at the start of later frames.
//! - Requests reach the app through a channel; `PrintCraftApp` answers them at the start of a
//!   frame, so they see and change exactly what the user would.
//!
//! Methods (JSON in, JSON out):
//! - `ui.state`: open documents, active document, page, zoom, page errors, mode, panels, dialog,
//!   notice.
//! - `ui.inspect {query?, role?, limit?}`: widgets in tree order with `id` (a string), `role`, `label`,
//!   `value`, `rect` (points), `enabled`, `toggled`, `selected`, `clickable`, `depth`.
//! - `ui.click {id}` | `{label}` | `{x, y, button?}`: click a widget (by its AccessKit action) or a
//!   point (`button`: primary or secondary, for context menus).
//! - `ui.drag {from: [x, y], to: [x, y], steps?, modifiers?}`: press, move and release (drawing
//!   comments, selecting text, moving comments). `ui.state` reports `pages_on_screen` to aim at.
//! - `ui.type {text}`, `ui.key {key, modifiers?}`: keyboard input to the focused widget / app.
//! - `ui.command {id}`: run a registry command (as the menu would). `ui.commands` lists them.
//! - `ui.set {key, value}`: the view options of the command line (`--page`, `--zoom`, …).
//! - `ui.open {path}`: open a file.
//! - `ui.screenshot {region?}`: PNG of the window (base64), optionally cropped to a rect.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use egui::accesskit::{self, Action, NodeId};
use serde_json::{Value, json};

pub type Reply = Result<Value, String>;

/// Seconds to wait for frames (input to be handled, a screenshot to be taken) before reporting
/// that the window is not being drawn. While a window is hidden, minimized or fully covered,
/// eframe keeps calling `logic` but runs no egui pass, so input and screenshots wait.
const NOT_DRAWN_TIMEOUT: f64 = 5.0;

/// Wall-clock seconds (egui's own clock stops while the window is not drawn).
fn now_secs() -> f64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START.get_or_init(std::time::Instant::now).elapsed().as_secs_f64()
    }
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() / 1000.0
    }
}

fn not_drawn(what: &str) -> String {
    format!(
        "{what} did not happen within {NOT_DRAWN_TIMEOUT:.0} s: the window is not being drawn (it may be hidden, minimized or covered); bring it to the front and retry"
    )
}

/// One request from a client, answered on `reply`.
pub struct ControlRequest {
    pub method: String,
    pub params: Value,
    pub reply: Sender<Reply>,
}

/// Sends requests to the app (from the transport thread or a test).
#[derive(Clone)]
pub struct ControlClient {
    tx: Sender<ControlRequest>,
    ctx: egui::Context,
}

impl ControlClient {
    /// Queue a request; the reply arrives on the returned receiver once the app has handled it.
    pub fn send(&self, method: &str, params: Value) -> Receiver<Reply> {
        let (reply, rx) = channel();
        let req = ControlRequest { method: method.into(), params, reply };
        if let Err(e) = self.tx.send(req) {
            let _ = e.0.reply.send(Err("the app has closed".into()));
        }
        self.ctx.request_repaint();
        rx
    }
}

/// State shared between the plugin (frame hooks) and the app.
#[derive(Default)]
struct Shared {
    nodes: HashMap<NodeId, accesskit::Node>,
    root: Option<NodeId>,
    focus: Option<NodeId>,
    /// Event batches to inject, one batch per frame.
    inject: VecDeque<Vec<egui::Event>>,
    /// Real egui passes so far (counted in `output_hook`, which `logic`-only calls never reach).
    passes: u64,
}

/// The egui plugin half of the control channel.
pub struct ControlPlugin {
    shared: Arc<Mutex<Shared>>,
}

impl egui::Plugin for ControlPlugin {
    fn debug_name(&self) -> &'static str {
        "printcraft-control"
    }

    fn input_hook(&mut self, ctx: &egui::Context, input: &mut egui::RawInput) {
        let Ok(mut s) = self.shared.lock() else { return };
        if let Some(batch) = s.inject.pop_front() {
            input.events.extend(batch);
        }
        if !s.inject.is_empty() {
            ctx.request_repaint();
        }
    }

    fn output_hook(&mut self, _ctx: &egui::Context, output: &mut egui::FullOutput) {
        let Ok(mut s) = self.shared.lock() else { return };
        s.passes += 1;
        let Some(update) = &output.platform_output.accesskit_update else { return };
        s.nodes = update.nodes.iter().cloned().collect();
        s.root = update.tree.as_ref().map(|t| t.root);
        s.focus = Some(update.focus);
    }
}

enum Pending {
    /// Answer after `frames` more frames (the injected input has been handled by then).
    Frames {
        /// Answer once this many egui passes have run (the injected input has been handled).
        until_pass: u64,
        since: f64,
        reply: Sender<Reply>,
        value: Value,
    },
    Screenshot {
        tag: u64,
        region: Option<egui::Rect>,
        reply: Sender<Reply>,
        /// When it was requested (egui time, seconds).
        since: f64,
    },
}

/// The app half: the request queue and requests waiting for later frames.
pub struct Control {
    rx: Receiver<ControlRequest>,
    shared: Arc<Mutex<Shared>>,
    pending: Vec<Pending>,
    next_tag: u64,
}

/// Install the control channel on `ctx`: returns the app half and a client.
pub fn attach(ctx: &egui::Context) -> (Control, ControlClient) {
    let shared = Arc::new(Mutex::new(Shared::default()));
    ctx.add_plugin(ControlPlugin { shared: shared.clone() });
    ctx.enable_accesskit();
    let (tx, rx) = channel();
    (Control { rx, shared, pending: Vec::new(), next_tag: 1 }, ControlClient { tx, ctx: ctx.clone() })
}

/// What a request needs from the app (implemented by `PrintCraftApp`).
pub(crate) trait Host {
    fn state(&self) -> Value;
    fn command(&mut self, id: &str) -> Reply;
    fn commands(&self) -> Value;
    fn set(&mut self, key: &str, value: &str) -> Reply;
    fn open(&mut self, path: &str) -> Reply;
}

impl Control {
    /// Handle new requests and finish waiting ones. Call at the start of every frame.
    pub(crate) fn tick(&mut self, ctx: &egui::Context, host: &mut impl Host) {
        self.finish_pending(ctx);
        while let Ok(req) = self.rx.try_recv() {
            match self.handle(ctx, host, &req.method, &req.params) {
                Handled::Now(r) => {
                    let _ = req.reply.send(r);
                }
                Handled::AfterFrames(frames, value) => {
                    let until_pass = self.passes() + u64::from(frames);
                    self.pending.push(Pending::Frames { until_pass, since: now_secs(), reply: req.reply, value });
                }
                Handled::Screenshot(region) => {
                    let tag = self.next_tag;
                    self.next_tag += 1;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::new(tag)));
                    self.pending.push(Pending::Screenshot { tag, region, reply: req.reply, since: now_secs() });
                }
            }
        }
        if !self.pending.is_empty() {
            ctx.request_repaint();
        }
    }

    fn finish_pending(&mut self, ctx: &egui::Context) {
        let shots: Vec<(u64, Arc<egui::ColorImage>)> = ctx.input(|i| {
            i.raw
                .events
                .iter()
                .filter_map(|e| match e {
                    egui::Event::Screenshot { user_data, image, .. } => {
                        user_data.data.as_ref().and_then(|d| d.downcast_ref::<u64>()).map(|tag| (*tag, image.clone()))
                    }
                    _ => None,
                })
                .collect()
        });
        let ppp = ctx.pixels_per_point();
        let now = now_secs();
        let passes = self.passes();
        let mut keep = Vec::new();
        for p in self.pending.drain(..) {
            match p {
                Pending::Frames { until_pass, reply, value, .. } if passes >= until_pass => {
                    let _ = reply.send(Ok(value));
                }
                Pending::Frames { since, reply, .. } if now - since > NOT_DRAWN_TIMEOUT => {
                    // The agent is told it failed, so it must not happen later either.
                    if let Ok(mut sh) = self.shared.lock() {
                        sh.inject.clear();
                    }
                    let _ = reply.send(Err(not_drawn("handling the input")));
                }
                p @ Pending::Frames { .. } => keep.push(p),
                Pending::Screenshot { tag, region, reply, since } => match shots.iter().find(|(t, _)| *t == tag) {
                    Some((_, image)) => {
                        let _ = reply.send(screenshot_png(image, region, ppp));
                    }
                    // The platform skips painting windows that are hidden, minimized or fully
                    // covered, so no screenshot ever arrives: say so instead of hanging.
                    None if now - since > NOT_DRAWN_TIMEOUT => {
                        let _ = reply.send(Err(not_drawn("the screenshot")));
                    }
                    None => keep.push(Pending::Screenshot { tag, region, reply, since }),
                },
            }
        }
        self.pending = keep;
    }

    fn passes(&self) -> u64 {
        self.shared.lock().map(|s| s.passes).unwrap_or(0)
    }

    fn inject(&self, batches: Vec<Vec<egui::Event>>) -> u32 {
        let n = batches.len() as u32;
        if let Ok(mut s) = self.shared.lock() {
            s.inject.extend(batches);
        }
        // The last batch is handled during the frame it is injected into; answer one frame later.
        n + 1
    }

    fn handle(&mut self, ctx: &egui::Context, host: &mut impl Host, method: &str, p: &Value) -> Handled {
        let str_param = |k: &str| p.get(k).and_then(Value::as_str).ok_or_else(|| format!("{method}: missing string parameter {k}"));
        let r: Result<Handled, String> = (|| match method {
            "ui.state" => Ok(Handled::Now(Ok(host.state()))),
            "ui.commands" => Ok(Handled::Now(Ok(host.commands()))),
            "ui.command" => Ok(Handled::Now(host.command(str_param("id")?))),
            "ui.set" => {
                let value = match p.get("value") {
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                    None => return Err("ui.set: missing parameter value".into()),
                };
                Ok(Handled::Now(host.set(str_param("key")?, &value)))
            }
            "ui.open" => Ok(Handled::Now(host.open(str_param("path")?))),
            "ui.inspect" => Ok(Handled::Now(Ok(self.inspect(p)))),
            "ui.click" => self.click(p),
            "ui.drag" => self.drag(p),
            "ui.type" => {
                let text = str_param("text")?.to_string();
                Ok(Handled::AfterFrames(self.inject(vec![vec![egui::Event::Text(text)]]), json!({ "typed": true })))
            }
            "ui.key" => {
                let name = str_param("key")?;
                let key = egui::Key::from_name(name)
                    .ok_or_else(|| format!("ui.key: unknown key {name:?} (egui key names: A, Enter, Escape, ArrowDown, F5, …)"))?;
                let modifiers = modifiers(p.get("modifiers"))?;
                let ev = |pressed| egui::Event::Key { key, physical_key: None, pressed, repeat: false, modifiers };
                Ok(Handled::AfterFrames(self.inject(vec![vec![ev(true)], vec![ev(false)]]), json!({ "key": name })))
            }
            "ui.screenshot" => {
                let region = match p.get("region") {
                    None | Some(Value::Null) => None,
                    Some(r) => Some(rect_param(r)?),
                };
                ctx.request_repaint();
                Ok(Handled::Screenshot(region))
            }
            other => Err(format!(
                "unknown method {other:?} (ui.state, ui.inspect, ui.click, ui.type, ui.key, ui.command, ui.commands, ui.set, ui.open, ui.screenshot)"
            )),
        })();
        r.unwrap_or_else(|e| Handled::Now(Err(e)))
    }

    fn inspect(&self, p: &Value) -> Value {
        let query = p.get("query").and_then(Value::as_str).map(str::to_lowercase);
        let role = p.get("role").and_then(Value::as_str).map(str::to_lowercase);
        let limit = p.get("limit").and_then(Value::as_u64).unwrap_or(500) as usize;
        let Ok(s) = self.shared.lock() else { return json!({ "widgets": [] }) };
        let mut out = Vec::new();
        let mut total = 0usize;
        let mut stack: Vec<(NodeId, usize)> = s.root.map(|r| vec![(r, 0)]).unwrap_or_default();
        while let Some((id, depth)) = stack.pop() {
            let Some(node) = s.nodes.get(&id) else { continue };
            for c in node.children().iter().rev() {
                stack.push((*c, depth + 1));
            }
            let w = widget(id, node, depth, s.focus == Some(id));
            let text =
                format!("{} {} {}", w["label"].as_str().unwrap_or(""), w["value"].as_str().unwrap_or(""), w["description"].as_str().unwrap_or(""))
                    .to_lowercase();
            let role_ok = role.as_ref().is_none_or(|r| w["role"].as_str().is_some_and(|x| x.to_lowercase() == *r));
            let query_ok = query.as_ref().is_none_or(|q| text.contains(q.as_str()));
            if role_ok && query_ok && id != s.root.unwrap_or(id) {
                total += 1;
                if out.len() < limit {
                    out.push(w);
                }
            }
        }
        json!({ "widgets": out, "count": total, "truncated": total > out.len() })
    }

    /// Press at `from`, move to `to` in `steps` frames, release (drawing, selecting text, moving).
    fn drag(&mut self, p: &Value) -> Result<Handled, String> {
        let point = |k: &str| -> Result<egui::Pos2, String> {
            match p.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_f64).collect::<Vec<_>>()).as_deref() {
                Some([x, y]) => Ok(egui::pos2(*x as f32, *y as f32)),
                _ => Err(format!("ui.drag: {k} must be [x, y] in points")),
            }
        };
        let (from, to) = (point("from")?, point("to")?);
        let steps = p.get("steps").and_then(Value::as_u64).unwrap_or(8).clamp(1, 200) as usize;
        let modifiers = modifiers(p.get("modifiers"))?;
        let button = |pos, pressed| egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed, modifiers };
        let mut frames = vec![vec![egui::Event::PointerMoved(from)], vec![button(from, true)]];
        for k in 1..=steps {
            frames.push(vec![egui::Event::PointerMoved(from + (to - from) * (k as f32 / steps as f32))]);
        }
        frames.push(vec![button(to, false)]);
        let n = self.inject(frames);
        Ok(Handled::AfterFrames(n, json!({ "dragged": [[from.x, from.y], [to.x, to.y]] })))
    }

    fn click(&mut self, p: &Value) -> Result<Handled, String> {
        if let (Some(x), Some(y)) = (p.get("x").and_then(Value::as_f64), p.get("y").and_then(Value::as_f64)) {
            let pos = egui::pos2(x as f32, y as f32);
            let which = match p.get("button").and_then(Value::as_str).unwrap_or("primary") {
                "primary" | "left" => egui::PointerButton::Primary,
                "secondary" | "right" => egui::PointerButton::Secondary,
                other => return Err(format!("ui.click: unknown button {other:?} (primary, secondary)")),
            };
            let button = |pressed| egui::Event::PointerButton { pos, button: which, pressed, modifiers: egui::Modifiers::NONE };
            let frames = self.inject(vec![vec![egui::Event::PointerMoved(pos)], vec![button(true)], vec![button(false)]]);
            return Ok(Handled::AfterFrames(frames, json!({ "clicked": [x, y] })));
        }
        let s = self.shared.lock().map_err(|_| "control state poisoned")?;
        let id = match (p.get("id"), p.get("label").and_then(Value::as_str)) {
            (Some(id), _) => {
                let id: u64 =
                    id.as_u64().or_else(|| id.as_str().and_then(|s| s.parse().ok())).ok_or("ui.click: id must be a widget id from ui.inspect")?;
                let id = NodeId(id);
                if !s.nodes.contains_key(&id) {
                    return Err(format!("ui.click: no widget with id {} on screen (run ui.inspect again)", id.0));
                }
                id
            }
            (None, Some(label)) => {
                let want = label.to_lowercase();
                let matches: Vec<NodeId> = s
                    .nodes
                    .iter()
                    .filter(|(_, n)| n.supports_action(Action::Click) && !n.is_disabled() && n.label().is_some_and(|l| l.to_lowercase() == want))
                    .map(|(id, _)| *id)
                    .collect();
                match matches.as_slice() {
                    [one] => *one,
                    [] => return Err(format!("ui.click: no enabled clickable widget labelled {label:?} (try ui.inspect with query)")),
                    many => return Err(format!("ui.click: {} widgets are labelled {label:?}; click one by id", many.len())),
                }
            }
            (None, None) => return Err("ui.click: pass id, label, or x and y".into()),
        };
        let node = &s.nodes[&id];
        if node.is_disabled() {
            return Err(format!("ui.click: widget {} ({}) is disabled", id.0, node.label().unwrap_or("unlabelled")));
        }
        let label = node.label().map(str::to_owned);
        let action = accesskit::ActionRequest { action: Action::Click, target_tree: accesskit::TreeId::ROOT, target_node: id, data: None };
        drop(s);
        let frames = self.inject(vec![vec![egui::Event::AccessKitActionRequest(action)]]);
        Ok(Handled::AfterFrames(frames, json!({ "clicked": id.0.to_string(), "label": label })))
    }
}

enum Handled {
    Now(Reply),
    AfterFrames(u32, Value),
    Screenshot(Option<egui::Rect>),
}

fn widget(id: NodeId, n: &accesskit::Node, depth: usize, focused: bool) -> Value {
    let rect = n.bounds().map(|b| [b.x0, b.y0, b.x1, b.y1]);
    let mut w = json!({
        // A string: 64-bit ids don't survive JSON parsers that use doubles.
        "id": id.0.to_string(),
        "role": format!("{:?}", n.role()),
        "depth": depth,
        "enabled": !n.is_disabled(),
        "clickable": n.supports_action(Action::Click),
    });
    let mut more = serde_json::Map::new();
    let obj = &mut more;
    if let Some(l) = n.label() {
        obj.insert("label".into(), json!(l));
    }
    if let Some(v) = n.value() {
        obj.insert("value".into(), json!(v));
    }
    if let Some(d) = n.description() {
        obj.insert("description".into(), json!(d));
    }
    if let Some(r) = rect {
        obj.insert("rect".into(), json!(r));
    }
    if let Some(t) = n.toggled() {
        obj.insert("toggled".into(), json!(format!("{t:?}").to_lowercase()));
    }
    if let Some(s) = n.is_selected() {
        obj.insert("selected".into(), json!(s));
    }
    if focused {
        obj.insert("focused".into(), json!(true));
    }
    if let Value::Object(m) = &mut w {
        m.extend(more);
    }
    w
}

fn modifiers(v: Option<&Value>) -> Result<egui::Modifiers, String> {
    let mut m = egui::Modifiers::NONE;
    for name in v.and_then(Value::as_array).into_iter().flatten() {
        match name.as_str().unwrap_or("") {
            "command" | "cmd" => m.command = true,
            "shift" => m.shift = true,
            "alt" | "option" => m.alt = true,
            "ctrl" | "control" => m.ctrl = true,
            "mac_cmd" => m.mac_cmd = true,
            other => return Err(format!("ui.key: unknown modifier {other:?} (command, shift, alt, ctrl)")),
        }
    }
    // "command" is ⌘ on macOS and Ctrl elsewhere, as egui expects.
    if m.command {
        if cfg!(target_os = "macos") {
            m.mac_cmd = true;
        } else {
            m.ctrl = true;
        }
    }
    Ok(m)
}

fn rect_param(v: &Value) -> Result<egui::Rect, String> {
    let a: Vec<f32> = v.as_array().map(|a| a.iter().filter_map(Value::as_f64).map(|f| f as f32).collect()).unwrap_or_default();
    match a.as_slice() {
        [x0, y0, x1, y1] if x1 > x0 && y1 > y0 => Ok(egui::Rect::from_min_max(egui::pos2(*x0, *y0), egui::pos2(*x1, *y1))),
        _ => Err("region must be [x0, y0, x1, y1] in points".into()),
    }
}

/// Encode (a region of) a screenshot as PNG; the reply carries base64 data and the size.
fn screenshot_png(image: &egui::ColorImage, region: Option<egui::Rect>, ppp: f32) -> Reply {
    let [w, h] = image.size;
    let (x0, y0, x1, y1) = match region {
        Some(r) => {
            let px = |v: f32, max: usize| ((v * ppp).round().max(0.0) as usize).min(max);
            (px(r.min.x, w), px(r.min.y, h), px(r.max.x, w), px(r.max.y, h))
        }
        None => (0, 0, w, h),
    };
    if x1 <= x0 || y1 <= y0 {
        return Err("the region is outside the window".into());
    }
    let mut rgba = Vec::with_capacity((x1 - x0) * (y1 - y0) * 4);
    for y in y0..y1 {
        for px in &image.pixels[y * w + x0..y * w + x1] {
            rgba.extend_from_slice(&px.to_srgba_unmultiplied());
        }
    }
    let (cw, ch) = ((x1 - x0) as u32, (y1 - y0) as u32);
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(&mut out, cw, ch);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut writer = enc.write_header().map_err(|e| e.to_string())?;
    writer.write_image_data(&rgba).map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())?;
    use base64::Engine as _;
    Ok(json!({ "png_base64": base64::engine::general_purpose::STANDARD.encode(out), "width": cw, "height": ch, "pixels_per_point": ppp }))
}

impl Host for crate::PrintCraftApp {
    fn state(&self) -> Value {
        let active = self.active.and_then(|i| self.views.get(i));
        let docs: Vec<Value> = self
            .views
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                let d = self.session.get(v.id)?;
                Some(json!({ "tab": i, "doc": v.id.0, "name": d.name, "path": d.path, "pages": d.info.pages.len(), "dirty": d.dirty, "active": self.active == Some(i) }))
            })
            .collect();
        json!({
            "documents": docs,
            "active": active.map(|v| json!({
                "doc": v.id.0,
                "page": v.current + 1,
                "zoom_percent": (v.zoom * 100.0).round(),
                "fit": format!("{:?}", v.fit),
                "layout": format!("{:?}", v.layout),
                "organize": v.organize,
                "find_open": v.find.is_some(),
                "page_errors": v.page_errors().iter().map(|(p, e)| json!({ "page": p + 1, "error": e })).collect::<Vec<_>>(),
                // Where pages are on screen (points), to aim ui.click / ui.drag at page content.
                "pages_on_screen": v.visible_page_rects().iter().map(|(p, r)| json!({ "page": p + 1, "rect": [r.min.x, r.min.y, r.max.x, r.max.y] })).collect::<Vec<_>>(),
                "selected_comment": v.comments.selected.map(|(p, i)| json!({ "page": p + 1, "index": i + 1 })),
                "comment_composer_open": v.comments.composer.is_some(),
            })),
            "quick_tool": match self.quick_tool {
                crate::QuickTool::Select => "select".to_string(),
                crate::QuickTool::Hand => "hand".to_string(),
                crate::QuickTool::Crop => "crop".to_string(),
                crate::QuickTool::Redact => "redact".to_string(),
                crate::QuickTool::AddText => "add-text".to_string(),
                crate::QuickTool::EditText => "edit-text".to_string(),
                crate::QuickTool::Link => "link".to_string(),
                crate::QuickTool::SignArea { certify: false } => "sign".to_string(),
                crate::QuickTool::SignArea { certify: true } => "certify".to_string(),
                crate::QuickTool::MarqueeZoom => "marquee-zoom".to_string(),
                crate::QuickTool::Snapshot => "snapshot".to_string(),
                crate::QuickTool::Stamp(k) => format!("stamp-{}", k.name().trim_start_matches("PC").to_ascii_lowercase()),
                crate::QuickTool::CustomStamp(i) => format!("custom-stamp-{i}"),
                crate::QuickTool::Fill(f) => format!("fill-{}", f.command().trim_start_matches("sign.fill.")),
                crate::QuickTool::Field(f) => format!("field-{}", f.command().trim_start_matches("form.add.")),
                crate::QuickTool::Comment(t) => t.command().trim_start_matches("comment.").to_string(),
            },
            "home": self.active.is_none(),
            "mode": format!("{:?}", self.mode),
            "left_panel": if self.left_open { json!(format!("{:?}", self.left)) } else { Value::Null },
            "right_panel": self.right.map(|r| format!("{r:?}")),
            "dialog": self.dialog.map(|d| format!("{d:?}")),
            "palette_open": self.palette_open,
            "theme": format!("{:?}", self.theme),
            "notice": self.toast.as_ref().map(|t| t.0.clone()),
            "password_prompt": self.password_prompt.is_some(),
            "close_prompt": self.close_request.is_some(),
        })
    }

    fn command(&mut self, id: &str) -> Reply {
        let spec = printcraft_engine::commands::command(id).ok_or_else(|| format!("unknown command {id:?} (see ui.commands)"))?;
        if !self.command_enabled(spec) {
            return Err(format!("{id} is disabled right now"));
        }
        self.execute(id);
        Ok(json!({ "ran": id }))
    }

    fn commands(&self) -> Value {
        let list: Vec<Value> = printcraft_engine::commands::COMMANDS
            .iter()
            .map(|c| json!({ "id": c.id, "label": c.label, "menu": c.menu, "enabled": self.command_enabled(c), "shortcut": c.shortcut.map(|s| s.label(cfg!(target_os = "macos"))) }))
            .collect();
        json!({ "commands": list })
    }

    fn set(&mut self, key: &str, value: &str) -> Reply {
        self.set_option(key, value).map(|()| json!({ "set": key, "value": value }))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn open(&mut self, path: &str) -> Reply {
        let before = self.views.len();
        self.open_path(path);
        if self.views.len() > before || self.password_prompt.is_some() {
            Ok(json!({ "opened": path, "password_prompt": self.password_prompt.is_some() }))
        } else {
            Err(self.toast.as_ref().map(|t| t.0.clone()).unwrap_or_else(|| format!("couldn't open {path}")))
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn open(&mut self, _path: &str) -> Reply {
        Err("ui.open needs a file system; on the web, drop the file on the page".into())
    }
}

// ---- transport (native only) -----------------------------------------------------------------

/// Where a running app's control channel can be reached (written to the `--control` file).
#[cfg(not(target_arch = "wasm32"))]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
}

/// Listener policy. The token is 256 bits. `allowlist` is the most any client may be granted;
/// [`Capability::JavaScriptRun`] is absent unless the operator names it.
#[cfg(not(target_arch = "wasm32"))]
pub struct ControlConfig {
    pub token: String,
    pub allowlist: printcraft_guard::CapabilitySet,
    pub absolute_ttl: std::time::Duration,
    pub idle_ttl: std::time::Duration,
}

#[cfg(not(target_arch = "wasm32"))]
impl ControlConfig {
    /// Build a config from explicit arguments, then `PRINTCRAFT_CONTROL_*` environment variables.
    pub fn resolve(token: Option<String>, token_file: Option<&std::path::Path>, capabilities: Option<&str>, untrusted: bool) -> Result<Self, String> {
        if untrusted && capabilities.is_some() {
            return Err("use either --control-untrusted or --control-capabilities, not both".into());
        }
        let file = token_file.map(std::path::Path::to_path_buf);
        let (supplied, file) = printcraft_guard::control_token_inputs(token, file);
        let token = printcraft_guard::server_token(supplied.as_deref(), file.as_deref()).map_err(|e| e.to_string())?;
        let from_env = std::env::var("PRINTCRAFT_CONTROL_CAPABILITIES").ok();
        let listed = capabilities.map(str::to_string).or(from_env);
        let env_untrusted = std::env::var("PRINTCRAFT_CONTROL_UNTRUSTED").ok().as_deref() == Some("1");
        let allowlist = if untrusted || (env_untrusted && capabilities.is_none()) {
            printcraft_guard::CapabilitySet::narrow()
        } else if let Some(list) = listed.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            printcraft_guard::CapabilitySet::parse_list(list).map_err(|e| e.to_string())?
        } else {
            printcraft_guard::CapabilitySet::operator_default()
        };
        Ok(Self { token, allowlist, absolute_ttl: printcraft_guard::SESSION_TTL, idle_ttl: printcraft_guard::SESSION_TTL })
    }
}

/// Listen on `127.0.0.1` (random port) with a fresh token and the operator allowlist
/// (everything except [`printcraft_guard::Capability::JavaScriptRun`]).
#[cfg(not(target_arch = "wasm32"))]
pub fn serve(client: ControlClient) -> std::io::Result<Endpoint> {
    let token = printcraft_guard::generate_token().map_err(|e| std::io::Error::other(e.to_string()))?;
    serve_with(
        client,
        ControlConfig {
            token,
            allowlist: printcraft_guard::CapabilitySet::operator_default(),
            absolute_ttl: printcraft_guard::SESSION_TTL,
            idle_ttl: printcraft_guard::SESSION_TTL,
        },
    )
}

/// Listen on `127.0.0.1` and forward requests that pass authentication and the capability gate.
///
/// Protocol: newline-delimited JSON-RPC 2.0. The first request on a connection must be
/// `auth` with the bearer token. No other method is dispatched before that. A client that
/// omits `capabilities` receives only `DocumentRead` and `UiInspect`.
#[cfg(not(target_arch = "wasm32"))]
pub fn serve_with(client: ControlClient, config: ControlConfig) -> std::io::Result<Endpoint> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let local = listener.local_addr()?;
    if !printcraft_guard::is_loopback(local.ip()) {
        return Err(std::io::Error::other("control channel refused a non-loopback bind"));
    }
    let port = local.port();
    let token = config.token.clone();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let limiter = printcraft_guard::ConnectionLimiter::new(printcraft_guard::MAX_CONNECTIONS);
    std::thread::Builder::new().name("printcraft-control".into()).spawn(move || {
        for stream in listener.incoming().flatten() {
            let Some(permit) = limiter.try_acquire() else {
                let _ = reject_connection(&stream, &rpc_error(Value::Null, -32005, "too many connections"));
                continue;
            };
            let client = client.clone();
            let expected = config.token.clone();
            let allowlist = config.allowlist.clone();
            let in_flight = Arc::clone(&in_flight);
            let absolute = config.absolute_ttl;
            let idle = config.idle_ttl;
            let _ = std::thread::Builder::new().name("printcraft-control-conn".into()).spawn(move || {
                let _permit = permit;
                serve_connection(stream, client, expected, allowlist, absolute, idle, in_flight.as_ref());
            });
        }
    })?;
    Ok(Endpoint { port, token })
}

#[cfg(not(target_arch = "wasm32"))]
fn reject_connection(stream: &std::net::TcpStream, reply: &Value) -> std::io::Result<()> {
    let mut stream = stream.try_clone()?;
    let _ = printcraft_guard::configure_stream(&stream);
    write_reply(&mut stream, reply)
}

#[cfg(not(target_arch = "wasm32"))]
fn serve_connection(
    stream: std::net::TcpStream,
    client: ControlClient,
    expected: String,
    allowlist: printcraft_guard::CapabilitySet,
    absolute: std::time::Duration,
    idle: std::time::Duration,
    in_flight: &std::sync::atomic::AtomicUsize,
) {
    use std::io::BufReader;
    if printcraft_guard::configure_stream(&stream).is_err() {
        return;
    }
    match stream.peer_addr() {
        Ok(addr) if printcraft_guard::is_loopback(addr.ip()) => {}
        _ => return,
    }
    let Ok(read) = stream.try_clone() else { return };
    let mut write = stream;
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    let mut session: Option<(printcraft_guard::Session, printcraft_guard::CapabilitySet)> = None;
    let gate = ControlGate { client: &client, expected: &expected, allowlist: &allowlist, absolute, idle, in_flight };
    while let Ok(frame) = printcraft_guard::read_bounded_line(&mut reader, &mut line) {
        let (reply, close) = match frame {
            printcraft_guard::LineRead::Eof => break,
            printcraft_guard::LineRead::TooLong => {
                (rpc_error(Value::Null, -32005, &format!("request exceeds {} bytes", printcraft_guard::MAX_REQUEST_BYTES)), true)
            }
            printcraft_guard::LineRead::Line if line.trim().is_empty() => continue,
            printcraft_guard::LineRead::Line => {
                let text = line.trim_end_matches(['\r', '\n']);
                dispatch_line(text, &gate, &mut session)
            }
        };
        if write_reply(&mut write, &reply).is_err() || close {
            break;
        }
    }
}

/// Shared inputs for one control connection. Grouped so dispatch stays under Clippy's argument cap.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy)]
struct ControlGate<'a> {
    client: &'a ControlClient,
    expected: &'a str,
    allowlist: &'a printcraft_guard::CapabilitySet,
    absolute: std::time::Duration,
    idle: std::time::Duration,
    in_flight: &'a std::sync::atomic::AtomicUsize,
}

#[cfg(not(target_arch = "wasm32"))]
fn dispatch_line(
    line: &str,
    gate: &ControlGate<'_>,
    session: &mut Option<(printcraft_guard::Session, printcraft_guard::CapabilitySet)>,
) -> (Value, bool) {
    use printcraft_guard::{AuditEvent, CapabilitySet, authenticate, check_json_depth, emit_audit, try_acquire_global};
    let ControlGate { client, expected, allowlist, absolute, idle, in_flight } = *gate;
    let msg: Value = match serde_json::from_str(line) {
        Ok(msg) => msg,
        Err(e) => return (rpc_error(Value::Null, -32700, &format!("parse error: {e}")), false),
    };
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    if let Err(e) = check_json_depth(&msg) {
        return (rpc_error(id, -32005, &e.to_string()), false);
    }
    if session.is_none() {
        let decision = authenticate(line, expected, allowlist, &CapabilitySet::narrow());
        if !decision.ok {
            let event = AuditEvent::new("unauthenticated", "auth", None, "deny", "unauthenticated", std::time::Duration::ZERO, None);
            emit_audit(&event);
            return (rpc_error(decision.id, -32001, "authentication required"), true);
        }
        let mut security = printcraft_guard::Session::with_limits(absolute, idle, 1);
        let _ = security.touch();
        let names = decision.granted.names();
        let event = AuditEvent::new(security.id(), "auth", Some(names.join(",")), "allow", "ok", std::time::Duration::ZERO, None);
        emit_audit(&event);
        let reply = json!({
            "jsonrpc": "2.0",
            "id": decision.id,
            "result": { "ok": true, "session": security.id(), "capabilities": names, "expires_in_secs": security.expires_in_secs() },
        });
        *session = Some((security, decision.granted));
        return (reply, false);
    }
    let Some((security, caps)) = session.as_mut() else {
        return (rpc_error(id, -32001, "authentication required"), true);
    };
    if security.touch().is_err() {
        let event = AuditEvent::new(security.id(), "auth", None, "deny", "expired", std::time::Duration::ZERO, None);
        emit_audit(&event);
        return (rpc_error(id, -32004, "session expired"), true);
    }
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    if let Some(missing) = missing_capability(method, &params, caps) {
        let event = AuditEvent::new(security.id(), method, Some(missing.name().into()), "deny", "denied", std::time::Duration::ZERO, None);
        emit_audit(&event);
        return (rpc_error(id, -32003, &format!("capability denied: {}", missing.name())), false);
    }
    let Some(_global) = try_acquire_global(in_flight, printcraft_guard::MAX_IN_FLIGHT) else {
        let event = AuditEvent::new(security.id(), method, None, "deny", "budget", std::time::Duration::ZERO, None);
        emit_audit(&event);
        return (rpc_error(id, -32005, "too many in-flight requests"), false);
    };
    let _slot = match security.try_begin() {
        Ok(slot) => slot,
        Err(_) => {
            let event = AuditEvent::new(security.id(), method, None, "deny", "budget", std::time::Duration::ZERO, None);
            emit_audit(&event);
            return (rpc_error(id, -32005, "too many in-flight requests"), false);
        }
    };
    let started = std::time::Instant::now();
    let session_id = security.id().to_string();
    let rx = client.send(method, params.clone());
    let (reply, outcome) = match rx.recv_timeout(printcraft_guard::IO_TIMEOUT) {
        Ok(Ok(v)) => (json!({ "jsonrpc": "2.0", "id": id, "result": v }), "ok"),
        Ok(Err(e)) => (rpc_error(id, -32000, &e), "error"),
        Err(_) => (rpc_error(id, -32002, "the app did not answer within 30 s"), "error"),
    };
    let path = params.get("path").and_then(Value::as_str).map(printcraft_guard::redact_path);
    let event = AuditEvent::new(&session_id, method, None, "allow", outcome, started.elapsed(), path);
    emit_audit(&event);
    (reply, false)
}

#[cfg(not(target_arch = "wasm32"))]
fn missing_capability(method: &str, params: &Value, caps: &printcraft_guard::CapabilitySet) -> Option<printcraft_guard::Capability> {
    use printcraft_guard::Capability;
    let needed = match method {
        "ui.state" | "ui.inspect" | "ui.commands" | "ui.screenshot" => vec![Capability::DocumentRead, Capability::UiInspect],
        "ui.click" | "ui.drag" | "ui.type" | "ui.key" => vec![Capability::UiControl],
        "ui.open" => vec![Capability::FilesystemRead, Capability::DocumentRead],
        "ui.set" => ui_set_capabilities(params),
        "ui.command" => ui_command_capabilities(params),
        _ => return None,
    };
    needed.into_iter().find(|cap| !caps.contains(*cap))
}

#[cfg(not(target_arch = "wasm32"))]
fn param_str<'a>(params: &'a Value, key: &str) -> &'a str {
    params.get(key).and_then(Value::as_str).unwrap_or("")
}

#[cfg(not(target_arch = "wasm32"))]
fn ui_set_capabilities(params: &Value) -> Vec<printcraft_guard::Capability> {
    use printcraft_guard::Capability;
    let key = param_str(params, "key");
    let value = param_str(params, "value");
    if key == "theme" || (key == "dialog" && value == "preferences") {
        vec![Capability::PreferencesWrite]
    } else if key == "dialog" && matches!(value, "js-console" | "document-js") {
        vec![Capability::JavaScriptRun, Capability::UiControl]
    } else {
        vec![Capability::UiControl]
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn ui_command_capabilities(params: &Value) -> Vec<printcraft_guard::Capability> {
    use printcraft_guard::Capability;
    let id = param_str(params, "id");
    if id == "tools.js_console" || id.starts_with("js.") || id.contains("javascript") {
        vec![Capability::JavaScriptRun, Capability::UiControl]
    } else if id == "app.preferences" {
        vec![Capability::PreferencesWrite, Capability::UiControl]
    } else if id.starts_with("help.") {
        vec![Capability::ApplicationControl]
    } else if id == "file.open" {
        vec![Capability::FilesystemRead, Capability::DocumentRead, Capability::UiControl]
    } else {
        vec![Capability::UiControl]
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn write_reply(write: &mut impl std::io::Write, reply: &Value) -> std::io::Result<()> {
    let bytes = printcraft_guard::fit_reply(reply);
    write.write_all(&bytes)?;
    write.write_all(b"\n")?;
    write.flush()
}

#[cfg(not(target_arch = "wasm32"))]
fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

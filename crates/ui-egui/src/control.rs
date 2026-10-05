//! The UI control channel (M3.9): lets an agent see and drive the running app.
//!
//! **Opt-in only.** Nothing here runs unless the app is started with `--control <file>` (or a
//! test attaches a [`ControlClient`]). The transport ([`serve`]) listens on loopback only, on a
//! random port. The first line on each connection must be `auth` with a 256-bit bearer token
//! (written to `<file>`, mode `0600`). See `SECURITY.md`. Stdio MCP does not use this token.
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
//
// Personal use: one 256-bit bearer token gates method dispatch. There is no capability list
// and no audit log. Budgets: 16 connections, 1 MiB request lines, 8 MiB replies.

#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufRead, Write};
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

/// Maximum encoded JSON request line, including its newline.
#[cfg(not(target_arch = "wasm32"))]
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Maximum encoded JSON reply, including its newline.
#[cfg(not(target_arch = "wasm32"))]
pub const MAX_RESPONSE_BYTES: usize = 8 << 20;
/// Maximum simultaneously serviced TCP connections per listener.
#[cfg(not(target_arch = "wasm32"))]
pub const MAX_CONNECTIONS: usize = 16;

#[cfg(not(target_arch = "wasm32"))]
const TOKEN_BYTES: usize = 32;
#[cfg(not(target_arch = "wasm32"))]
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;
#[cfg(not(target_arch = "wasm32"))]
const IO_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(not(target_arch = "wasm32"))]
const AUTH_METHOD: &str = "auth";

/// Where a running app's control channel can be reached (written to the `--control` file).
#[cfg(not(target_arch = "wasm32"))]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
}

/// Result of reading one bounded JSON-lines frame.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineRead {
    Eof,
    Line,
    TooLong,
}

/// Listen on `127.0.0.1` (random port) with a fresh 256-bit token.
///
/// Protocol: newline-delimited JSON-RPC 2.0. The first request on a connection must be
/// `{"method": "auth", "params": {"token": …}}`; anything else closes the connection.
#[cfg(not(target_arch = "wasm32"))]
pub fn serve(client: ControlClient) -> std::io::Result<Endpoint> {
    serve_with_token(client, generate_token()?)
}

/// Listen on `127.0.0.1` using `token` (64 hexadecimal characters). Refuses to bind when the
/// token is the wrong shape.
#[cfg(not(target_arch = "wasm32"))]
pub fn serve_with_token(client: ControlClient, token: String) -> std::io::Result<Endpoint> {
    let token = token.trim().to_ascii_lowercase();
    validate_token(&token)?;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let local = listener.local_addr()?;
    ensure_loopback(local)?;
    let port = local.port();
    let expected = token.clone();
    std::thread::Builder::new().name("printcraft-control".into()).spawn(move || accept_loop(listener, expected, client))?;
    Ok(Endpoint { port, token })
}

/// Resolve the listener's token. A missing token file is created (mode `0600` on Unix) and the
/// token is not returned anywhere else. Passing both a token and a file is an error. With
/// neither, a fresh token is returned for the caller to store in the `--control` file.
#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_server_token(supplied: Option<&str>, token_file: Option<&Path>) -> std::io::Result<String> {
    if supplied.is_some() && token_file.is_some() {
        return Err(std::io::Error::other("use either a control token or a control token file, not both"));
    }
    if let Some(token) = supplied {
        let token = token.trim().to_ascii_lowercase();
        validate_token(&token)?;
        return Ok(token);
    }
    let Some(path) = token_file else {
        return generate_token();
    };
    if path.exists() {
        return read_token_file(path);
    }
    let token = generate_token()?;
    match create_token_file(path, &token) {
        Ok(()) => Ok(token),
        Err(_) if path.exists() => read_token_file(path),
        Err(e) => Err(e),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn accept_loop(listener: std::net::TcpListener, token: String, client: ControlClient) {
    let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
    let token = Arc::<str>::from(token);
    for stream in listener.incoming().flatten() {
        if stream.peer_addr().ok().is_none_or(|addr| ensure_loopback(addr).is_err()) {
            continue;
        }
        let Some(permit) = limiter.try_acquire() else {
            let _ = configure_stream(&stream);
            let mut stream = stream;
            let _ = write_reply(&mut stream, &rpc_error(Value::Null, -32004, "connection limit reached"));
            continue;
        };
        let client = client.clone();
        let token = Arc::clone(&token);
        let _ = std::thread::Builder::new().name("printcraft-control-conn".into()).spawn(move || {
            let _permit = permit;
            serve_connection(stream, &token, client);
        });
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn serve_connection(stream: std::net::TcpStream, token: &str, client: ControlClient) {
    if configure_stream(&stream).is_err() {
        return;
    }
    let Ok(read) = stream.try_clone() else { return };
    let mut reader = std::io::BufReader::new(read);
    let mut write = stream;
    let mut line = String::new();
    let mut authed = false;
    loop {
        match read_bounded_line(&mut reader, &mut line) {
            Ok(LineRead::Eof) | Err(_) => break,
            Ok(LineRead::TooLong) => {
                let reply = rpc_error(Value::Null, -32005, &format!("request exceeds {MAX_REQUEST_BYTES} bytes"));
                let _ = write_reply(&mut write, &reply);
                break;
            }
            Ok(LineRead::Line) if line.trim().is_empty() => continue,
            Ok(LineRead::Line) => {}
        }
        let (reply, close) = if !authed {
            let (reply, ok) = authentication_reply(&line, token);
            authed = ok;
            (reply, !ok)
        } else {
            match serde_json::from_str::<Value>(&line) {
                Err(e) => (rpc_error(Value::Null, -32700, &format!("parse error: {e}")), false),
                Ok(msg) => {
                    let id = msg.get("id").cloned().unwrap_or(Value::Null);
                    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
                    let params = msg.get("params").cloned().unwrap_or(Value::Null);
                    let rx = client.send(method, params);
                    match rx.recv_timeout(IO_TIMEOUT) {
                        Ok(Ok(v)) => (json!({ "jsonrpc": "2.0", "id": id, "result": v }), false),
                        Ok(Err(e)) => (rpc_error(id, -32000, &e), false),
                        Err(_) => (rpc_error(id, -32002, "the app did not answer within 30 s"), false),
                    }
                }
            }
        };
        if write_reply(&mut write, &reply).is_err() || close {
            break;
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// The first frame. A failure carries no method result and does not echo the token.
#[cfg(not(target_arch = "wasm32"))]
fn authentication_reply(line: &str, expected: &str) -> (Value, bool) {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return (rpc_error(Value::Null, -32001, "authentication required"), false);
    };
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let supplied = msg.get("params").and_then(|p| p.get("token")).and_then(Value::as_str).unwrap_or("");
    if method == AUTH_METHOD && token_matches(expected, supplied) {
        (json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } }), true)
    } else {
        (rpc_error(id, -32001, "authentication required"), false)
    }
}

/// Compare fixed-width tokens without leaving early on a mismatching byte.
/// Hex digits are compared case-insensitively; the 256-bit value is unchanged.
#[cfg(not(target_arch = "wasm32"))]
fn token_matches(expected: &str, supplied: &str) -> bool {
    if expected.len() != TOKEN_HEX_LEN || supplied.len() != TOKEN_HEX_LEN {
        return false;
    }
    let mut different = 0u8;
    for (a, b) in expected.bytes().zip(supplied.bytes()) {
        different |= a.to_ascii_lowercase() ^ b.to_ascii_lowercase();
    }
    different == 0
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_token(token: &str) -> std::io::Result<()> {
    if token.len() == TOKEN_HEX_LEN && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(std::io::Error::other("control token must contain exactly 64 hexadecimal characters"))
    }
}

/// 256 random bits from the OS, lowercase hex.
#[cfg(not(target_arch = "wasm32"))]
fn generate_token() -> std::io::Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut token = String::with_capacity(TOKEN_HEX_LEN);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        let Some(hi) = HEX.get(hi).copied() else {
            return Err(std::io::Error::other("cannot encode control token"));
        };
        let Some(lo) = HEX.get(lo).copied() else {
            return Err(std::io::Error::other("cannot encode control token"));
        };
        token.push(char::from(hi));
        token.push(char::from(lo));
    }
    Ok(token)
}

#[cfg(not(target_arch = "wasm32"))]
fn ensure_loopback(addr: std::net::SocketAddr) -> std::io::Result<()> {
    if addr.ip().is_loopback() { Ok(()) } else { Err(std::io::Error::other(format!("{addr} is not a loopback address"))) }
}

#[cfg(not(target_arch = "wasm32"))]
fn read_bounded_line(reader: &mut impl BufRead, line: &mut String) -> std::io::Result<LineRead> {
    line.clear();
    let mut limited = std::io::Read::take(reader, (MAX_REQUEST_BYTES + 1) as u64);
    let n = limited.read_line(line)?;
    if n == 0 {
        Ok(LineRead::Eof)
    } else if n > MAX_REQUEST_BYTES {
        Ok(LineRead::TooLong)
    } else {
        Ok(LineRead::Line)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn read_token_file(path: &Path) -> std::io::Result<String> {
    let file = std::fs::File::open(path).map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
    let mut limited = std::io::Read::take(file, (TOKEN_HEX_LEN + 2) as u64);
    let mut token = String::new();
    std::io::Read::read_to_string(&mut limited, &mut token).map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
    let token = token.trim().to_ascii_lowercase();
    validate_token(&token)?;
    Ok(token)
}

#[cfg(not(target_arch = "wasm32"))]
fn create_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| std::io::Error::other(format!("{}: {e}", parent.display())))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "{token}").map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))
}

#[cfg(not(target_arch = "wasm32"))]
fn configure_stream(stream: &std::net::TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))
}

#[cfg(not(target_arch = "wasm32"))]
struct ConnectionLimiter {
    active: AtomicUsize,
    max: usize,
}

#[cfg(not(target_arch = "wasm32"))]
struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ConnectionLimiter {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(Self { active: AtomicUsize::new(0), max })
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            let next = current.checked_add(1)?;
            match self.active.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(ConnectionPermit { limiter: Arc::clone(self) }),
                Err(actual) => current = actual,
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct LimitedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

#[cfg(not(target_arch = "wasm32"))]
impl Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let room = self.maximum.saturating_sub(self.bytes.len());
        if buf.len() > room {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("response exceeds {} bytes", self.maximum)));
        }
        self.bytes.try_reserve(buf.len()).map_err(|error| std::io::Error::other(format!("response allocation failed: {error}")))?;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn encode_with_limit(value: &impl serde::Serialize, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut writer = LimitedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, value).map_err(|_| ())?;
    Ok(writer.bytes)
}

/// Encode one JSON-lines reply. An oversized payload becomes a short error that keeps `id`.
/// The operation may already have completed.
#[cfg(not(target_arch = "wasm32"))]
fn write_reply(out: &mut impl Write, reply: &Value) -> std::io::Result<()> {
    let encoded = match encode_with_limit(reply, MAX_RESPONSE_BYTES.saturating_sub(1)) {
        Ok(bytes) => bytes,
        Err(()) => {
            let error = rpc_error(
                reply.get("id").cloned().unwrap_or(Value::Null),
                -32003,
                &format!("response exceeds {MAX_RESPONSE_BYTES} bytes; operation may have completed"),
            );
            match encode_with_limit(&error, MAX_RESPONSE_BYTES.saturating_sub(1)) {
                Ok(bytes) => bytes,
                Err(()) => br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32003,"message":"response budget exceeded"}}"#.to_vec(),
            }
        }
    };
    out.write_all(&encoded)?;
    out.write_all(b"\n")?;
    out.flush()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod transport_tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    fn roundtrip(addr: std::net::SocketAddr, payloads: &[String]) -> Vec<Value> {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut replies = Vec::new();
        for payload in payloads {
            writeln!(stream, "{payload}").unwrap();
            stream.flush().unwrap();
            let mut line = String::new();
            let n = reader.read_line(&mut line).unwrap();
            assert!(n > 0, "connection closed before a reply");
            replies.push(serde_json::from_str(&line).unwrap());
        }
        replies
    }

    #[test]
    fn generated_tokens_are_256_bits_and_files_stay_private() {
        let token = generate_token().unwrap();
        validate_token(&token).unwrap();
        assert_eq!(token.len(), 64);
        assert!(token_matches(&token, &token.to_ascii_uppercase()));
        assert!(!token_matches(&token, &"ab".repeat(32)));
        let path = std::env::temp_dir().join(format!("printcraft-control-token-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let server = resolve_server_token(None, Some(&path)).unwrap();
        let again = resolve_server_token(None, Some(&path)).unwrap();
        assert_eq!(server, again);
        assert!(token_matches(&server, &again));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "token file mode {mode:o}");
        }
        let err = resolve_server_token(Some(&server), Some(&path)).unwrap_err();
        assert!(err.to_string().contains("not both"), "{err}");
        match serve_with_token(attach(&egui::Context::default()).1, "short".into()) {
            Err(err) => assert!(err.to_string().contains("64 hexadecimal"), "{err}"),
            Ok(_) => panic!("a short token must not open the listener"),
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn authentication_rejects_a_missing_or_wrong_token_without_a_result() {
        let token = generate_token().unwrap();
        let (reply, ok) = authentication_reply(r#"{"jsonrpc":"2.0","id":1,"method":"ui.state"}"#, &token);
        assert!(!ok);
        assert_eq!(reply["id"], 1);
        assert_eq!(reply["error"]["message"], "authentication required");
        assert!(reply.get("result").is_none());

        let wrong = "f".repeat(64);
        let line = json!({"jsonrpc":"2.0","id":2,"method":"auth","params":{"token": wrong}}).to_string();
        let (reply, ok) = authentication_reply(&line, &token);
        assert!(!ok);
        assert_eq!(reply["error"]["code"], -32001);
        let text = reply.to_string();
        assert!(!text.contains(&token));
        assert!(!text.contains(&wrong));

        let smuggled = json!({"jsonrpc":"2.0","id":3,"method":"ui.command","params":{"token": token}}).to_string();
        let (reply, ok) = authentication_reply(&smuggled, &token);
        assert!(!ok);
        assert_eq!(reply["error"]["message"], "authentication required");

        let upper = token.to_ascii_uppercase();
        let line = json!({"jsonrpc":"2.0","id":4,"method":"auth","params":{"token": upper}}).to_string();
        let (reply, ok) = authentication_reply(&line, &token);
        assert!(ok);
        assert_eq!(reply["result"]["ok"], true);
    }

    #[test]
    fn unauthenticated_and_wrong_token_are_rejected() {
        let (_control, client) = attach(&egui::Context::default());
        let ep = serve(client).unwrap();
        assert_eq!(ep.token.len(), 64);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], ep.port));

        let unauth = roundtrip(addr, &[json!({"jsonrpc":"2.0","id":1,"method":"ui.state"}).to_string()]);
        assert_eq!(unauth.len(), 1);
        assert_eq!(unauth[0]["error"]["code"], -32001);
        assert_eq!(unauth[0]["error"]["message"], "authentication required");
        assert!(unauth[0].get("result").is_none());

        let wrong = "ab".repeat(32);
        let bad = roundtrip(addr, &[json!({"jsonrpc":"2.0","id":2,"method":"auth","params":{"token": wrong}}).to_string()]);
        assert_eq!(bad[0]["error"]["message"], "authentication required");
        assert!(!bad[0].to_string().contains(&wrong));
        assert!(!bad[0].to_string().contains(&ep.token));

        let upper = ep.token.to_ascii_uppercase();
        let good = roundtrip(addr, &[json!({"jsonrpc":"2.0","id":3,"method":"auth","params":{"token": upper}}).to_string()]);
        assert_eq!(good[0]["result"]["ok"], true);
    }

    #[test]
    fn oversized_request_is_rejected_without_dispatch() {
        let (_control, client) = attach(&egui::Context::default());
        let ep = serve_with_token(client, "c".repeat(64)).unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", ep.port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1]).unwrap();
        let mut line = String::new();
        std::io::BufReader::new(stream).read_line(&mut line).unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["error"]["code"], -32005);
        assert!(reply["error"]["message"].as_str().unwrap().contains("request exceeds"));
        assert!(reply.get("result").is_none());
    }

    #[test]
    fn connection_limit_rejects_the_extra_client() {
        let (_control, client) = attach(&egui::Context::default());
        let ep = serve_with_token(client, "d".repeat(64)).unwrap();
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], ep.port));
        let mut held = Vec::new();
        for i in 0..MAX_CONNECTIONS {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            writeln!(stream, "{}", json!({"jsonrpc":"2.0","id":i,"method":"auth","params":{"token":"d".repeat(64)}})).unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["result"]["ok"], true, "{line}");
            held.push((stream, reader));
        }
        let extra = TcpStream::connect(addr).unwrap();
        extra.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut line = String::new();
        std::io::BufReader::new(extra).read_line(&mut line).unwrap();
        assert!(line.contains("connection limit reached"), "{line}");
        drop(held);
    }

    #[test]
    fn oversized_reply_is_replaced_and_keeps_the_id() {
        let reply = json!({"jsonrpc":"2.0","id":7,"result":"x".repeat(MAX_RESPONSE_BYTES)});
        let mut out = Vec::new();
        write_reply(&mut out, &reply).unwrap();
        assert!(out.len() < 1024, "{}", out.len());
        assert_eq!(out.iter().filter(|&&byte| byte == b'\n').count(), 1);
        let error: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(error["id"], 7);
        assert!(error["error"]["message"].as_str().unwrap().contains("operation may have completed"));
        assert!(!error.to_string().contains("xxxx"));
    }

    #[test]
    fn non_loopback_addresses_are_refused() {
        let v4: std::net::SocketAddr = "0.0.0.0:9".parse().unwrap();
        let v6: std::net::SocketAddr = "[::]:9".parse().unwrap();
        assert!(ensure_loopback(v4).unwrap_err().to_string().contains("loopback"));
        assert!(ensure_loopback(v6).unwrap_err().to_string().contains("loopback"));
        ensure_loopback("127.0.0.1:9".parse().unwrap()).unwrap();
        ensure_loopback("[::1]:9".parse().unwrap()).unwrap();
    }

    #[test]
    fn bounded_reader_rejects_an_oversized_line() {
        let input = format!("{}\n", "x".repeat(MAX_REQUEST_BYTES + 1));
        let mut reader = std::io::Cursor::new(input);
        let mut line = String::new();
        assert_eq!(read_bounded_line(&mut reader, &mut line).unwrap(), LineRead::TooLong);
    }

    #[test]
    fn connection_limiter_releases_capacity() {
        let limiter = ConnectionLimiter::new(1);
        let permit = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert!(limiter.try_acquire().is_some());
    }
}

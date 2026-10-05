//! Local automation security for PrintCraft.
//!
//! Tokens, capability sets, session deadlines, request budgets, path and URL checks,
//! and structured audit events. Transports (TCP control, stdio MCP, the CLI) apply
//! these rules; this crate does not open sockets or touch documents.
//!
//! Audit events name a session id, never a bearer token, and path fields are handles
//! rather than the path text.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

/// The first request on every TCP connection must use this method.
pub const AUTH_METHOD: &str = "auth";
/// Maximum encoded JSON request line, including its newline.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Maximum encoded JSON reply, including its newline.
pub const MAX_RESPONSE_BYTES: usize = 8 << 20;
/// Maximum simultaneously serviced TCP connections per listener.
pub const MAX_CONNECTIONS: usize = 16;
/// Maximum commands or tool calls in one batch.
pub const MAX_BATCH_STEPS: usize = 256;
/// Maximum requests a session may have in flight at once.
pub const MAX_IN_FLIGHT: usize = 4;
/// Absolute and idle session lifetime. Re-authentication is required after either.
pub const SESSION_TTL: Duration = Duration::from_secs(60 * 60);
/// Idle/read and write timeout for loopback TCP connections.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// JSON nesting accepted on an automation request. Deeper documents are rejected.
pub const MAX_JSON_DEPTH: usize = 64;

const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;
const AUDIT_CAP: usize = 256;

/// Why a guard check failed. Messages are stable enough for an agent to branch on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// The request itself is malformed.
    BadRequest(String),
    /// Authenticated, but the session lacks `capability`.
    Denied(String),
    /// The session must authenticate again.
    Expired,
    /// A byte, step, connection, or in-flight budget was exceeded.
    Budget(String),
    /// Reading or creating a token file failed.
    Io(String),
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::BadRequest(m) | GuardError::Io(m) | GuardError::Budget(m) => f.write_str(m),
            GuardError::Denied(cap) => write!(f, "capability denied: {cap}"),
            GuardError::Expired => f.write_str("session expired"),
        }
    }
}

impl std::error::Error for GuardError {}

fn bad(message: impl Into<String>) -> GuardError {
    GuardError::BadRequest(message.into())
}

// ---- capabilities ----------------------------------------------------------------------------

/// One class of automation effect. Sessions hold an explicit set; nothing is implied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Read open documents, metadata, text, and rendered pages.
    DocumentRead,
    /// Change document state (edits, form values, saves of content).
    DocumentWrite,
    /// Read the running UI (state, widget tree, screenshots, command list).
    UiInspect,
    /// Inject input or run a UI command that is not a more specific capability.
    UiControl,
    /// Read files under a granted root (or the operator's ambient filesystem).
    FilesystemRead,
    /// Write files under a granted root (or the operator's ambient filesystem).
    FilesystemWrite,
    /// Change application preferences.
    PreferencesWrite,
    /// Quit, print to a device, list printers, or other process-wide control.
    ApplicationControl,
    /// Run or install Acrobat JavaScript, or turn the engine's JavaScript on.
    JavaScriptRun,
}

impl Capability {
    pub const ALL: [Capability; 9] = [
        Capability::DocumentRead,
        Capability::DocumentWrite,
        Capability::UiInspect,
        Capability::UiControl,
        Capability::FilesystemRead,
        Capability::FilesystemWrite,
        Capability::PreferencesWrite,
        Capability::ApplicationControl,
        Capability::JavaScriptRun,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Capability::DocumentRead => "DocumentRead",
            Capability::DocumentWrite => "DocumentWrite",
            Capability::UiInspect => "UiInspect",
            Capability::UiControl => "UiControl",
            Capability::FilesystemRead => "FilesystemRead",
            Capability::FilesystemWrite => "FilesystemWrite",
            Capability::PreferencesWrite => "PreferencesWrite",
            Capability::ApplicationControl => "ApplicationControl",
            Capability::JavaScriptRun => "JavaScriptRun",
        }
    }

    pub fn parse(name: &str) -> Option<Capability> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// The capabilities a session holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    caps: Vec<Capability>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self { caps: Vec::new() }
    }

    pub fn insert(&mut self, cap: Capability) {
        if !self.caps.contains(&cap) {
            self.caps.push(cap);
        }
    }

    pub fn contains(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.caps.iter().copied()
    }

    /// Every capability except [`Capability::JavaScriptRun`].
    ///
    /// This is the operator default for a process the user launched (`printcraft-cli run` / `mcp`)
    /// and the default allowlist for an opt-in `--control` listener.
    pub fn operator_default() -> Self {
        let mut set = Self::new();
        for cap in Capability::ALL {
            if cap != Capability::JavaScriptRun {
                set.insert(cap);
            }
        }
        set
    }

    /// What a TCP client receives when it authenticates without asking for capabilities.
    pub fn narrow() -> Self {
        let mut set = Self::new();
        set.insert(Capability::DocumentRead);
        set.insert(Capability::UiInspect);
        set
    }

    /// Parse a comma-separated list. Empty input is an empty set. Unknown names fail.
    pub fn parse_list(text: &str) -> Result<Self, GuardError> {
        let mut set = Self::new();
        for part in text.split(',') {
            let name = part.trim();
            if name.is_empty() {
                continue;
            }
            let Some(cap) = Capability::parse(name) else {
                return Err(bad(format!(
                    "unknown capability {name:?} (DocumentRead, DocumentWrite, UiInspect, UiControl, FilesystemRead, FilesystemWrite, PreferencesWrite, ApplicationControl, JavaScriptRun)"
                )));
            };
            set.insert(cap);
        }
        Ok(set)
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.caps.iter().copied().map(Capability::name).collect()
    }
}

// ---- tokens ----------------------------------------------------------------------------------

/// Result of reading one bounded JSON-lines frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineRead {
    Eof,
    Line,
    TooLong,
}

/// Read one line without buffering more than [`MAX_REQUEST_BYTES`] plus one byte.
pub fn read_bounded_line(reader: &mut impl BufRead, line: &mut String) -> std::io::Result<LineRead> {
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

fn random_bytes(bytes: &mut [u8]) -> Result<(), GuardError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::fill(bytes).map_err(|e| GuardError::Io(format!("cannot generate random bytes: {e}")))
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = bytes;
        Err(GuardError::Io("control tokens are not available on the web build".into()))
    }
}

/// Generate a 256-bit bearer token with the operating system CSPRNG.
pub fn generate_token() -> Result<String, GuardError> {
    let mut bytes = [0u8; TOKEN_BYTES];
    random_bytes(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

/// A session id. Shorter than a token so the two are not interchangeable.
pub fn generate_session_id() -> Result<String, GuardError> {
    let mut bytes = [0u8; 16];
    random_bytes(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut token = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        token.push(HEX[(byte >> 4) as usize] as char);
        token.push(HEX[(byte & 0x0f) as usize] as char);
    }
    token
}

/// Accept only the fixed-width hexadecimal representation emitted by [`generate_token`].
pub fn validate_token(token: &str) -> Result<(), GuardError> {
    if token.len() != TOKEN_HEX_LEN || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("control token must contain exactly 64 hexadecimal characters"));
    }
    Ok(())
}

/// Compare fixed-width tokens without an early exit on a mismatching byte.
pub fn token_matches(expected: &str, supplied: &str) -> bool {
    if expected.len() != TOKEN_HEX_LEN || supplied.len() != TOKEN_HEX_LEN {
        return false;
    }
    let mut different = 0u8;
    for (a, b) in expected.bytes().zip(supplied.bytes()) {
        different |= a.to_ascii_lowercase() ^ b.to_ascii_lowercase();
    }
    different == 0
}

fn read_token_file(path: &Path) -> Result<String, GuardError> {
    let token = std::fs::read_to_string(path).map_err(|e| GuardError::Io(format!("{}: {e}", path.display())))?;
    let token = token.trim().to_owned();
    validate_token(&token)?;
    Ok(token.to_ascii_lowercase())
}

fn create_token_file(path: &Path, token: &str) -> Result<(), GuardError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| GuardError::Io(format!("{}: {e}", parent.display())))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| GuardError::Io(format!("{}: {e}", path.display())))?;
    writeln!(file, "{token}").map_err(|e| GuardError::Io(format!("{}: {e}", path.display())))
}

/// Resolve a server token. With no supplied token or file, a fresh token is returned.
/// A missing token file is created owner-only; an existing one is read and validated.
pub fn server_token(supplied: Option<&str>, token_file: Option<&Path>) -> Result<String, GuardError> {
    if supplied.is_some() && token_file.is_some() {
        return Err(bad("use either a control token or a control token file, not both"));
    }
    if let Some(token) = supplied {
        validate_token(token)?;
        return Ok(token.to_ascii_lowercase());
    }
    let token = generate_token()?;
    let Some(path) = token_file else {
        return Ok(token);
    };
    match read_token_file(path) {
        Ok(existing) => Ok(existing),
        Err(GuardError::Io(_)) if !path.exists() => match create_token_file(path, &token) {
            Ok(()) => Ok(token),
            Err(GuardError::Io(_)) if path.exists() => read_token_file(path),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// `PRINTCRAFT_CONTROL_TOKEN` and `PRINTCRAFT_CONTROL_TOKEN_FILE`, when the caller did not pass them.
pub fn control_token_inputs(supplied: Option<String>, token_file: Option<PathBuf>) -> (Option<String>, Option<PathBuf>) {
    let supplied = supplied.filter(|s| !s.is_empty()).or_else(|| std::env::var("PRINTCRAFT_CONTROL_TOKEN").ok());
    let token_file = token_file.or_else(|| std::env::var_os("PRINTCRAFT_CONTROL_TOKEN_FILE").map(PathBuf::from));
    (supplied, token_file)
}

/// Decide an authentication frame. The token is compared and then dropped; it is not copied
/// into the result. `requested` is `None` when the client omitted `capabilities` (the session
/// then receives `narrow`, still intersected with `allowlist`). An explicit list is intersected
/// with `allowlist`. [`Capability::JavaScriptRun`] is never added unless it was requested and allowlisted.
pub fn authenticate(line: &str, expected_token: &str, allowlist: &CapabilitySet, narrow: &CapabilitySet) -> AuthDecision {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return AuthDecision::reject(Value::Null),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params");
    let supplied = params.and_then(|p| p.get("token")).and_then(Value::as_str).unwrap_or("");
    if method != AUTH_METHOD || !token_matches(expected_token, supplied) {
        return AuthDecision::reject(id);
    }
    let requested = match params.and_then(|p| p.get("capabilities")) {
        None => None,
        Some(Value::Array(items)) => {
            let mut set = CapabilitySet::new();
            for item in items {
                let Some(name) = item.as_str() else {
                    return AuthDecision::reject(id);
                };
                let Some(cap) = Capability::parse(name) else {
                    return AuthDecision::reject(id);
                };
                set.insert(cap);
            }
            Some(set)
        }
        Some(_) => return AuthDecision::reject(id),
    };
    let base = requested.as_ref().unwrap_or(narrow);
    let mut granted = CapabilitySet::new();
    for cap in base.iter() {
        if allowlist.contains(cap) {
            granted.insert(cap);
        }
    }
    AuthDecision { id, ok: true, granted }
}

/// Outcome of [`authenticate`]. `granted` is empty when `ok` is false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDecision {
    pub id: Value,
    pub ok: bool,
    pub granted: CapabilitySet,
}

impl AuthDecision {
    fn reject(id: Value) -> Self {
        Self { id, ok: false, granted: CapabilitySet::new() }
    }
}

// ---- session and connections -----------------------------------------------------------------

/// Counts active connections and returns a permit only while below the configured maximum.
pub struct ConnectionLimiter {
    active: AtomicUsize,
    max: usize,
}

impl ConnectionLimiter {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self { active: AtomicUsize::new(0), max })
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(ConnectionPermit { limiter: Arc::clone(self) }),
                Err(actual) => current = actual,
            }
        }
    }
}

pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One authenticated automation session. The id is not a secret; the token is not stored here.
pub struct Session {
    id: String,
    created: Instant,
    last: Instant,
    absolute_ttl: Duration,
    idle_ttl: Duration,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: usize,
    force_expired: AtomicBool,
}

impl Session {
    pub fn new() -> Self {
        Self::with_limits(SESSION_TTL, SESSION_TTL, MAX_IN_FLIGHT)
    }

    pub fn with_limits(absolute_ttl: Duration, idle_ttl: Duration, max_in_flight: usize) -> Self {
        let now = Instant::now();
        let id = generate_session_id().unwrap_or_else(|_| "session".into());
        Self {
            id,
            created: now,
            last: now,
            absolute_ttl,
            idle_ttl,
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: max_in_flight.max(1),
            force_expired: AtomicBool::new(false),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn expired(&self) -> bool {
        if self.force_expired.load(Ordering::Acquire) {
            return true;
        }
        let now = Instant::now();
        now.saturating_duration_since(self.created) > self.absolute_ttl || now.saturating_duration_since(self.last) > self.idle_ttl
    }

    /// Record activity. Fails when the absolute or idle deadline has passed.
    pub fn touch(&mut self) -> Result<(), GuardError> {
        if self.expired() {
            return Err(GuardError::Expired);
        }
        self.last = Instant::now();
        Ok(())
    }

    pub fn expires_in_secs(&self) -> u64 {
        let now = Instant::now();
        let abs = self.absolute_ttl.saturating_sub(now.saturating_duration_since(self.created));
        let idle = self.idle_ttl.saturating_sub(now.saturating_duration_since(self.last));
        abs.min(idle).as_secs()
    }

    /// Mark the session expired. Intended for tests; an in-process caller can already do anything.
    pub fn force_expired(&self) {
        self.force_expired.store(true, Ordering::Release);
    }

    pub fn try_begin(&self) -> Result<InFlight, GuardError> {
        if self.expired() {
            return Err(GuardError::Expired);
        }
        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            if current >= self.max_in_flight {
                return Err(GuardError::Budget(format!("too many in-flight requests (limit {})", self.max_in_flight)));
            }
            match self.in_flight.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(InFlight { counter: Arc::clone(&self.in_flight) }),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds one in-flight slot until dropped.
pub struct InFlight {
    counter: Arc<AtomicUsize>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A process-wide in-flight cap shared by every connection on one listener.
pub fn try_acquire_global(counter: &AtomicUsize, max: usize) -> Option<GlobalInFlight<'_>> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= max {
            return None;
        }
        match counter.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(GlobalInFlight { counter }),
            Err(actual) => current = actual,
        }
    }
}

pub struct GlobalInFlight<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for GlobalInFlight<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn check_batch_len(steps: usize) -> Result<(), GuardError> {
    if steps > MAX_BATCH_STEPS {
        return Err(GuardError::Budget(format!("batch exceeds {MAX_BATCH_STEPS} steps")));
    }
    Ok(())
}

/// Apply idle and write timeouts before handing a socket to a connection worker.
pub fn configure_stream(stream: &std::net::TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))
}

pub fn is_loopback(ip: std::net::IpAddr) -> bool {
    ip.is_loopback()
}

// ---- reply budgets ---------------------------------------------------------------------------

struct LimitedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.maximum.saturating_sub(self.bytes.len()) {
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

fn encode_with_limit(value: &Value, maximum: usize) -> Result<Vec<u8>, GuardError> {
    let mut writer = LimitedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, value).map_err(|error| GuardError::Budget(format!("response encoding failed: {error}")))?;
    Ok(writer.bytes)
}

/// Serialize `reply` if it fits. Otherwise a small error with the same id, noting that the
/// operation may already have completed. The returned bytes do not include a trailing newline.
pub fn fit_reply(reply: &Value) -> Vec<u8> {
    let maximum = MAX_RESPONSE_BYTES.saturating_sub(1);
    if let Ok(bytes) = encode_with_limit(reply, maximum) {
        return bytes;
    }
    let error = json!({
        "jsonrpc": "2.0",
        "id": reply.get("id").cloned().unwrap_or(Value::Null),
        "error": {
            "code": -32005,
            "message": format!("response exceeds {MAX_RESPONSE_BYTES} bytes; operation may have completed"),
        },
    });
    encode_with_limit(&error, maximum)
        .unwrap_or_else(|_| b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32005,\"message\":\"response budget exceeded\"}}".to_vec())
}

pub fn fit_reply_string(reply: &Value) -> String {
    String::from_utf8(fit_reply(reply))
        .unwrap_or_else(|_| "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32005,\"message\":\"response budget exceeded\"}}".to_string())
}

/// Reserve envelope space and bound retained batch results so many valid replies cannot
/// accumulate into one enormous batch response.
pub struct BatchReplyBudget {
    remaining: usize,
}

impl Default for BatchReplyBudget {
    fn default() -> Self {
        Self { remaining: MAX_RESPONSE_BYTES.saturating_sub(MAX_REQUEST_BYTES).saturating_sub(4096) }
    }
}

impl BatchReplyBudget {
    /// Call before retaining the result or running the next step.
    pub fn charge(&mut self, result: &Value) -> Result<(), GuardError> {
        let bytes = encode_with_limit(result, self.remaining.saturating_sub(1))?;
        self.remaining = self.remaining.saturating_sub(bytes.len().saturating_add(1));
        Ok(())
    }
}

/// Reject objects nested deeper than [`MAX_JSON_DEPTH`] before a transport dispatches them.
pub fn check_json_depth(value: &Value) -> Result<(), GuardError> {
    fn walk(value: &Value, depth: usize) -> Result<(), GuardError> {
        if depth > MAX_JSON_DEPTH {
            return Err(GuardError::Budget(format!("JSON nesting exceeds {MAX_JSON_DEPTH}")));
        }
        match value {
            Value::Array(items) => {
                for item in items {
                    walk(item, depth.saturating_add(1))?;
                }
            }
            Value::Object(map) => {
                for item in map.values() {
                    walk(item, depth.saturating_add(1))?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(value, 1)
}

// ---- paths and URLs --------------------------------------------------------------------------

const DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9",
];

fn hostile_chars(path: &str) -> bool {
    path.chars().any(|c| c == '\0' || c.is_control())
}

fn is_device_component(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or(component);
    let upper = base.to_ascii_uppercase();
    DEVICE_NAMES.contains(&upper.as_str())
}

/// A path used with no root: the operator's ambient filesystem. NUL and control characters are rejected.
pub fn check_ambient_path(path: &str) -> Result<(), GuardError> {
    if path.is_empty() || path.len() > 4096 {
        return Err(bad("path is empty or too long"));
    }
    if hostile_chars(path) {
        return Err(bad("path contains a control character"));
    }
    Ok(())
}

/// A path that must stay relative to a granted root.
///
/// Rejects absolute paths, parent traversal, alternate separators, Windows device names,
/// empty components, and trailing dots or spaces on a component.
pub fn check_rooted_path(path: &str) -> Result<(), GuardError> {
    if path.is_empty() || path.len() > 4096 {
        return Err(bad("path is empty or too long"));
    }
    if hostile_chars(path) || path.contains('\\') || path.contains(':') {
        return Err(bad("path contains a separator or character that is not allowed under --root"));
    }
    if path.starts_with('/') || path.starts_with('~') {
        return Err(bad("absolute paths are not allowed under --root"));
    }
    for component in path.split('/') {
        if component.is_empty() {
            return Err(bad("path contains an empty component"));
        }
        if component == ".." {
            return Err(bad("'..' is not allowed under --root"));
        }
        if component != "." && (component.ends_with('.') || component.ends_with(' ')) {
            return Err(bad("path component has a trailing dot or space"));
        }
        if is_device_component(component) {
            return Err(bad("path uses a device name"));
        }
    }
    Ok(())
}

/// A stable handle for audit logs. The path text is not recoverable from it.
pub fn redact_path(path: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("path#{hash:016x}")
}

/// Whether the UI may hand `url` to the system browser.
///
/// Allows `http`, `https`, and `mailto` only. `javascript:`, `file:`, `data:`, and anything
/// with userinfo, whitespace, or a missing host is rejected.
pub fn external_url_allowed(url: &str) -> bool {
    if url.is_empty() || url.len() > 2048 || url.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
        return false;
    }
    let lower = url.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("mailto:") {
        return mailto_ok(rest);
    }
    let rest = if let Some(rest) = lower.strip_prefix("https://") {
        rest
    } else if let Some(rest) = lower.strip_prefix("http://") {
        rest
    } else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.len() <= 5 => host,
        _ => authority,
    };
    host_ok(host)
}

fn host_ok(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        return host[1..host.len() - 1].parse::<std::net::Ipv6Addr>().is_ok();
    }
    if host.len() > 253 || !host.contains('.') {
        return false;
    }
    let mut labels = 0usize;
    for label in host.split('.') {
        labels = labels.saturating_add(1);
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return false;
        }
    }
    labels >= 2
}

fn mailto_ok(rest: &str) -> bool {
    let addr = rest.split(['?', '#']).next().unwrap_or("");
    if addr.is_empty() || addr.len() > 320 || addr.matches('@').count() != 1 {
        return false;
    }
    let Some((local, host)) = addr.split_once('@') else { return false };
    if local.is_empty() || local.len() > 64 || host.is_empty() {
        return false;
    }
    if addr.chars().any(|c| !c.is_ascii() || c == '/' || c == '\\') {
        return false;
    }
    host_ok(host) || host.eq_ignore_ascii_case("localhost")
}

// ---- audit -----------------------------------------------------------------------------------

/// One security decision. Serialized for logs; never carries a token, secret, or file bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub time_unix_ms: u64,
    pub session: String,
    pub method: String,
    pub capability: Option<String>,
    /// `allow` or `deny`.
    pub decision: &'static str,
    /// `ok`, `error`, `denied`, `expired`, `budget`, or `unauthenticated`.
    pub outcome: String,
    pub duration_ms: u64,
    /// [`redact_path`] output, when the call named a path.
    pub path: Option<String>,
}

impl AuditEvent {
    pub fn new(
        session: &str,
        method: &str,
        capability: Option<String>,
        decision: &'static str,
        outcome: impl Into<String>,
        duration: Duration,
        path: Option<String>,
    ) -> Self {
        let time_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0);
        Self {
            time_unix_ms,
            session: session.to_string(),
            method: method.to_string(),
            capability,
            decision,
            outcome: outcome.into(),
            duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            path,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "printcraft_audit": true,
            "time_unix_ms": self.time_unix_ms,
            "session": self.session,
            "method": self.method,
            "capability": self.capability,
            "decision": self.decision,
            "outcome": self.outcome,
            "duration_ms": self.duration_ms,
            "path": self.path,
        })
    }
}

/// Ring buffer of recent audit events.
#[derive(Clone, Debug, Default)]
pub struct AuditLog {
    events: VecDeque<AuditEvent>,
}

impl AuditLog {
    pub fn record(&mut self, event: AuditEvent) {
        if self.events.len() >= AUDIT_CAP {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn events(&self) -> impl Iterator<Item = &AuditEvent> {
        self.events.iter()
    }

    pub fn to_vec(&self) -> Vec<AuditEvent> {
        self.events.iter().cloned().collect()
    }
}

/// Write one JSON line to stderr when `PRINTCRAFT_AUDIT=1`, and always for denials.
/// The line is the event object only.
pub fn emit_audit(event: &AuditEvent) {
    let mirror = event.decision == "deny" || std::env::var("PRINTCRAFT_AUDIT").ok().as_deref() == Some("1");
    if !mirror {
        return;
    }
    let line = event.to_json().to_string();
    eprintln!("{line}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_256_bits_and_compared_in_full() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        validate_token(&a).unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(token_matches(&a, &a));
        assert!(token_matches(&a, &a.to_ascii_uppercase()));
        assert!(!token_matches(&a, &b));
        assert!(!token_matches(&a, "short"));
        assert!(!token_matches(&a, &format!("{a}00")));
        let mut flipped = a.clone();
        let last = flipped.pop().unwrap();
        flipped.push(if last == 'a' { 'b' } else { 'a' });
        assert!(!token_matches(&a, &flipped));
    }

    #[test]
    fn authentication_rejects_missing_and_wrong_tokens_before_any_grant() {
        let token = generate_token().unwrap();
        let allow = CapabilitySet::operator_default();
        let narrow = CapabilitySet::narrow();
        let denied = authenticate(r#"{"id":1,"method":"ui.state","params":{}}"#, &token, &allow, &narrow);
        assert!(!denied.ok);
        assert!(denied.granted.iter().next().is_none());
        let wrong = authenticate(&json!({"id": 2, "method": AUTH_METHOD, "params": {"token": "ab".repeat(32)}}).to_string(), &token, &allow, &narrow);
        assert!(!wrong.ok);
        let line = json!({"id": 3, "method": AUTH_METHOD, "params": {"token": token}}).to_string();
        let ok = authenticate(&line, &token, &allow, &narrow);
        assert!(ok.ok);
        assert!(ok.granted.contains(Capability::DocumentRead));
        assert!(ok.granted.contains(Capability::UiInspect));
        assert!(!ok.granted.contains(Capability::JavaScriptRun));
        assert!(!ok.granted.contains(Capability::UiControl));
        let asked = json!({
            "id": 4,
            "method": AUTH_METHOD,
            "params": {"token": token, "capabilities": ["UiControl", "JavaScriptRun", "DocumentRead"]},
        })
        .to_string();
        let partial = authenticate(&asked, &token, &allow, &narrow);
        assert!(partial.granted.contains(Capability::UiControl));
        assert!(partial.granted.contains(Capability::DocumentRead));
        assert!(!partial.granted.contains(Capability::JavaScriptRun));
        let strict = CapabilitySet::narrow();
        let blocked = authenticate(&asked, &token, &strict, &narrow);
        assert!(blocked.ok);
        assert!(!blocked.granted.contains(Capability::UiControl));
        assert!(blocked.granted.contains(Capability::DocumentRead));
    }

    #[test]
    fn bounded_reader_rejects_an_oversized_line() {
        let input = format!("{}\n", "x".repeat(MAX_REQUEST_BYTES + 1));
        let mut reader = std::io::Cursor::new(input);
        let mut line = String::new();
        assert_eq!(read_bounded_line(&mut reader, &mut line).unwrap(), LineRead::TooLong);
        assert_eq!(line.len(), MAX_REQUEST_BYTES + 1);
    }

    #[test]
    fn connection_limiter_releases_capacity() {
        let limiter = ConnectionLimiter::new(1);
        let permit = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn session_expiry_and_in_flight_fail_closed() {
        let session = Session::with_limits(Duration::from_secs(60), Duration::from_secs(60), 1);
        let hold = session.try_begin().unwrap();
        assert!(session.try_begin().is_err());
        drop(hold);
        assert!(session.try_begin().is_ok());
        session.force_expired();
        assert!(matches!(session.try_begin(), Err(GuardError::Expired)));
        assert!(check_batch_len(MAX_BATCH_STEPS).is_ok());
        assert!(check_batch_len(MAX_BATCH_STEPS + 1).is_err());
    }

    #[test]
    fn oversized_reply_is_one_complete_error_with_the_same_id() {
        let reply = json!({"jsonrpc": "2.0", "id": 7, "result": "x".repeat(MAX_RESPONSE_BYTES)});
        let bytes = fit_reply(&reply);
        assert!(bytes.len() < 1024, "{}", bytes.len());
        let error: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["id"], 7);
        assert!(error["error"]["message"].as_str().unwrap().contains("operation may have completed"));
    }

    #[test]
    fn batch_budget_stops_before_the_aggregate_is_exceeded() {
        let mut budget = BatchReplyBudget { remaining: 10 };
        budget.charge(&json!("abc")).unwrap();
        assert!(budget.charge(&json!("abc")).is_err());
    }

    #[test]
    fn rooted_paths_reject_traversal_devices_and_absolute_forms() {
        check_rooted_path("a.pdf").unwrap();
        check_rooted_path("in/scan.pdf").unwrap();
        check_rooted_path("./a.pdf").unwrap();
        for bad_path in ["../a.pdf", "/tmp/a.pdf", "in/../../etc/passwd", "C:a.pdf", "in\\a.pdf", "CON", "com1.txt", "a//b.pdf", "file.", ""] {
            assert!(check_rooted_path(bad_path).is_err(), "{bad_path}");
        }
        check_ambient_path("/tmp/a.pdf").unwrap();
        assert!(check_ambient_path("a\0b").is_err());
        let handle = redact_path("/secret/contract.pdf");
        assert!(!handle.contains("secret"));
        assert!(!handle.contains("contract"));
        assert_ne!(handle, redact_path("/secret/other.pdf"));
    }

    #[test]
    fn external_urls_allow_web_and_mail_only() {
        assert!(external_url_allowed("https://example.com/a"));
        assert!(external_url_allowed("HTTP://example.com"));
        assert!(external_url_allowed("https://localhost/x"));
        assert!(external_url_allowed("mailto:person@example.com"));
        assert!(external_url_allowed("mailto:person@example.com?subject=Hello"));
        for blocked in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,hi",
            "https://user:pass@example.com/",
            "https://example.com\\@evil.test/",
            "//example.com",
            "https:/example.com",
            " http://example.com",
            "vbscript:msgbox",
            "",
        ] {
            assert!(!external_url_allowed(blocked), "{blocked}");
        }
    }

    #[test]
    fn audit_events_omit_tokens_and_path_text() {
        let token = generate_token().unwrap();
        let event = AuditEvent::new(
            "sess",
            "js_run",
            Some("JavaScriptRun".into()),
            "deny",
            "denied",
            Duration::from_millis(3),
            Some(redact_path("/tmp/secret.pdf")),
        );
        let line = event.to_json().to_string();
        assert!(!line.contains(&token));
        assert!(!line.contains("secret.pdf"));
        assert!(line.contains("\"decision\":\"deny\""));
        assert!(line.contains("JavaScriptRun"));
        assert!(line.contains("printcraft_audit"));
        let mut log = AuditLog::default();
        for i in 0..AUDIT_CAP + 5 {
            log.record(AuditEvent::new("s", &format!("m{i}"), None, "allow", "ok", Duration::ZERO, None));
        }
        assert_eq!(log.to_vec().len(), AUDIT_CAP);
    }

    #[test]
    fn token_file_round_trips() {
        let path = std::env::temp_dir().join(format!("printcraft-guard-token-{}-{}.txt", std::process::id(), generate_session_id().unwrap()));
        let server = server_token(None, Some(&path)).unwrap();
        let again = server_token(None, Some(&path)).unwrap();
        assert_eq!(server, again);
        assert!(token_matches(&server, &again));
        std::fs::remove_file(&path).unwrap();
        assert!(server_token(Some("abcd"), None).is_err());
        assert!(server_token(Some(&server), Some(&path)).is_err());
    }

    #[test]
    fn json_depth_is_bounded() {
        let mut value = json!(1);
        for _ in 0..MAX_JSON_DEPTH + 2 {
            value = json!([value]);
        }
        assert!(check_json_depth(&value).is_err());
        assert!(check_json_depth(&json!({"a": [1, 2]})).is_ok());
    }
}

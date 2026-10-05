//! Which capability each tool needs. JavaScript is never implied by a write or a read.

use printcraft_guard::{Capability, CapabilitySet};
use serde_json::Value;

const JAVASCRIPT: &[&str] = &["js_run", "js_set_document_script", "js_document_scripts", "form_set_script", "form_actions", "form_set_actions"];

const JS_MUTATING: &[&str] = &["js_run", "js_set_document_script", "form_set_script", "form_set_actions"];

const FILE_READ: &[&str] = &[
    "doc_open",
    "page_insert_file",
    "doc_combine",
    "doc_import_data",
    "form_set_image",
    "stamp_custom",
    "page_replace",
    "page_add_image",
    "content_update",
    "doc_watermark",
    "doc_background",
    "ocr_recognize_files",
    "sign_document",
    "sign_trust",
    "form_merge_data",
    "doc_compare",
    "doc_compare_report",
    "doc_compare_mark",
    "action_run",
];

const FILE_WRITE: &[&str] = &[
    "doc_save",
    "page_extract",
    "doc_combine",
    "doc_split",
    "doc_export_data",
    "doc_export_images",
    "doc_export_text",
    "doc_export_all_images",
    "doc_export_office",
    "accessibility_report",
    "form_merge_data",
    "sign_id_create",
    "sign_document",
    "doc_print",
    "comments_summarize",
    "action_run",
    "doc_compare_report",
];

const APP: &[&str] = &["printers", "sign_keychain_ids", "doc_print"];

/// The first capability `have` is missing for this call, if any.
pub(crate) fn missing(have: &CapabilitySet, name: &str, args: &Value, read_only: bool) -> Option<Capability> {
    required(name, args, read_only).into_iter().find(|cap| !have.contains(*cap))
}

fn required(name: &str, args: &Value, read_only: bool) -> Vec<Capability> {
    let mut caps = Vec::new();
    if JAVASCRIPT.contains(&name) || (name == "action_run" && requests_javascript(args)) {
        caps.push(Capability::JavaScriptRun);
    }
    if name == "js_enabled" {
        caps.push(Capability::PreferencesWrite);
        if args.get("enabled").and_then(Value::as_bool) == Some(true) {
            caps.push(Capability::JavaScriptRun);
        }
    }
    if APP.contains(&name) {
        caps.push(Capability::ApplicationControl);
    }
    if FILE_READ.contains(&name) {
        caps.push(Capability::FilesystemRead);
    }
    if FILE_WRITE.contains(&name) {
        caps.push(Capability::FilesystemWrite);
    }
    if JS_MUTATING.contains(&name) {
        caps.push(Capability::DocumentWrite);
    } else if !caps
        .iter()
        .any(|c| matches!(c, Capability::DocumentRead | Capability::DocumentWrite | Capability::ApplicationControl | Capability::PreferencesWrite))
    {
        caps.push(if read_only { Capability::DocumentRead } else { Capability::DocumentWrite });
    } else if name == "js_document_scripts" || name == "form_actions" {
        caps.push(Capability::DocumentRead);
    }
    caps
}

pub(crate) fn requests_javascript(args: &Value) -> bool {
    args.get("steps")
        .and_then(Value::as_array)
        .is_some_and(|steps| steps.iter().any(|step| step.get("step").and_then(Value::as_str) == Some("run_javascript")))
        || args.get("action").and_then(Value::as_str).is_some_and(|name| name.to_ascii_lowercase().contains("javascript"))
}

/// A redacted handle for the first path-shaped argument, when there is one.
pub(crate) fn path_handle(args: &Value) -> Option<String> {
    for key in ["path", "folder", "out", "out_dir", "file"] {
        if let Some(path) = args.get(key).and_then(Value::as_str) {
            return Some(printcraft_guard::redact_path(path));
        }
    }
    args.get("paths").and_then(Value::as_array).and_then(|items| items.first()).and_then(Value::as_str).map(printcraft_guard::redact_path)
}

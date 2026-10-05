//! Links the app hands to the system browser.

use printcraft_ui_egui::PrintCraftApp;

#[test]
fn open_url_allows_http_https_and_mailto_and_blocks_other_schemes() {
    let mut app = PrintCraftApp::new();
    app.open_url("javascript:alert(1)");
    assert!(app.last_opened_url.is_none());
    let notice = app.toast.as_ref().map(|toast| toast.0.as_str()).unwrap_or("");
    assert!(notice.contains("Blocked"), "{notice}");

    app.open_url("https://example.com/a");
    assert_eq!(app.last_opened_url.as_deref(), Some("https://example.com/a"));

    app.last_opened_url = None;
    app.open_url("http://example.com/a");
    assert_eq!(app.last_opened_url.as_deref(), Some("http://example.com/a"));

    app.last_opened_url = None;
    app.open_url("mailto:hello@example.com");
    assert_eq!(app.last_opened_url.as_deref(), Some("mailto:hello@example.com"));

    for blocked in ["file:///etc/passwd", "data:text/html,hi", "https://user:secret@example.com/a", "https://example.com/a b"] {
        app.last_opened_url = None;
        app.open_url(blocked);
        assert!(app.last_opened_url.is_none(), "{blocked}");
    }
}

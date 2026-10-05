# PrintCraft automation security

This document describes the opt-in automation surfaces: the desktop UI control channel, `printcraft-cli run`, and the stdio MCP server. The ordinary GUI, with automation left off, does not open those listeners and is unchanged.

PrintCraft does not start an MCP server, register one with an agent, or listen on a port unless you ask. There is no MCP-to-TCP bridge. Prefer stdio. If you use the control channel, keep it on loopback and do not tunnel it.

## Trust boundaries

| Surface | Who is trusted | What they receive |
|---|---|---|
| Desktop app, no `--control` | The person at the keyboard | Full GUI. Acrobat JavaScript stays on unless Preferences turn it off. |
| `printcraft-cli run` and `printcraft-cli mcp` | The user who launched the process | Operator capabilities: everything except `JavaScriptRun`. Stdio is that user's trust boundary. There is no second authentication hop. |
| `printcraft --control FILE` | Whoever can read `FILE` and connect to `127.0.0.1` | A bearer token and an allowlist. A client that does not name capabilities receives only `DocumentRead` and `UiInspect`. |

In-process UI tests talk to the app through a channel, not TCP. That path is not a network boundary and is not capability-gated.

## Authentication

The control channel binds `127.0.0.1` on a random port and refuses a non-loopback local or peer address. The first JSON-RPC method on a connection must be `auth`. Any other method, including a method that arrives before `auth`, is rejected with `-32001` and the connection is closed. The token is not echoed.

The token is 256 bits from the operating-system CSPRNG, encoded as 64 hexadecimal characters. Comparison is constant-time and accepts only that exact width (case-insensitive). A wrong or truncated token is rejected the same way as a missing one.

Token sources, in order:

- `--control-token` or `PRINTCRAFT_CONTROL_TOKEN`
- `--control-token-file` or `PRINTCRAFT_CONTROL_TOKEN_FILE` (created owner-only if it does not exist; mode `0600` on Unix)
- a fresh token, written with the port and pid to the `--control` file (owner-only)

Do not put a token on a command line that is logged, and do not commit one. The process prints the path of the endpoint file, not the token. `PRINTCRAFT_AUDIT` logs never include it.

Successful `auth` returns `{ "ok": true, "session", "capabilities", "expires_in_secs" }`. An unknown capability name, or a `capabilities` value that is not an array, fails authentication.

## Capabilities

Denied unless the session holds them.

| Capability | Allows |
|---|---|
| `DocumentRead` | Inspect documents, pages, and read-only tools |
| `DocumentWrite` | Edits, including scripts that change the document |
| `UiInspect` | `ui.state`, `ui.inspect`, `ui.commands`, `ui.screenshot` |
| `UiControl` | Clicks, keys, commands, and most `ui.set` changes |
| `FilesystemRead` | Read paths the tool resolves |
| `FilesystemWrite` | Write paths the tool resolves |
| `PreferencesWrite` | Theme and the preferences dialog; `js_enabled` |
| `ApplicationControl` | Printing, keychain identity listing, Help commands |
| `JavaScriptRun` | `js_run`, document and field scripts, JavaScript actions, turning JavaScript on |

`JavaScriptRun` is off for automation unless it is both requested and present on the server allowlist. The engine's JavaScript preference is turned off when an `Automation` session is created, so field scripts do not run for an untrusted session. The desktop app's own preference stays on by default and is not consulted by the tool table.

Handshake for TCP:

1. The server allowlist defaults to every capability except `JavaScriptRun`.
2. A client that omits `capabilities` is granted only `DocumentRead` and `UiInspect`, intersected with that allowlist.
3. A client that sends `capabilities` is granted the intersection of that list and the allowlist.
4. `printcraft-cli ui` requests the capabilities its method needs and stops if the server did not grant them. It requests `JavaScriptRun` only for the JavaScript console and document-JavaScript dialog.

`--control-capabilities` and `PRINTCRAFT_CONTROL_CAPABILITIES` replace the allowlist; they do not add to it. Name every capability that session should be able to grant, including `JavaScriptRun` when scripts must run. `--control-untrusted` (or `PRINTCRAFT_CONTROL_UNTRUSTED=1` when no capability list was passed on the command line) selects the narrow set. Passing both a capability list and `--control-untrusted` is an error.

For `printcraft-cli run` and `mcp`, `--capabilities` / `PRINTCRAFT_CAPABILITIES` replace the operator set, and `--untrusted` / `PRINTCRAFT_UNTRUSTED=1` selects `DocumentRead` and `UiInspect`. The two flags together are an error.

A missing capability is `-32003` (`capability denied: …`) and does not close the TCP connection.

## Limits

| Limit | Value | Failure |
|---|---|---|
| Connections per listener | 16 | `-32005` too many connections |
| Request line | 1 MiB, including the newline | `-32005`, then the connection stops |
| Reply | 8 MiB, including the newline | `-32005`. The operation may already have completed |
| Batch steps | 256 | rejected before the batch runs |
| In flight | 4 per listener, 1 per TCP control session | `-32005` |
| Idle and absolute session life | 1 hour each | `-32004` session expired, connection closed |
| JSON depth | 64 | `-32005` |
| Read and write timeout | 30 s | `-32002` when the app does not answer |

`printcraft-cli run --script` applies the request-size, batch-length, and reply budgets. Image bytes written to disk are charged as a short summary, not as the PNG itself.

## Filesystem roots

With `--root`, every path a tool reads or writes must be relative to that directory. The check rejects absolute paths, `..`, backslash, `:`, NUL and other control characters, empty components, Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`), and a component that ends in a dot or a space. After that, the path is canonicalized and must stay inside the root, which rejects a symlink that points outside.

With no root, paths are the operator's own filesystem. Absolute paths are allowed. NUL and control characters are still rejected.

## URLs

`javascript:`, `file:`, and `data:` links from document JavaScript, link annotations, and buttons are not handed to the browser. `open_url` allows only `http`, `https`, and `mailto`, and rejects userinfo, whitespace, backslash, and a missing host.

Help ▸ Check for updates stays manual. The app does not check at startup and does not download or install a build. The GitHub response is capped at 1 MiB, and a release page is offered only when its URL starts with `https://github.com/storytold/printcraft/releases/` and the rest contains no `?`, `#`, or `\`. Anything else falls back to that releases list. Opening the page goes through `open_url` as a second check.

## Audit

Each allow or deny is an in-memory event: session id (not the token), method, capability, decision (`allow` or `deny`), outcome, duration, and a redacted path handle (`path#` plus a 64-bit hash). The ring holds 256 events. Denials are also written to stderr. `PRINTCRAFT_AUDIT=1` mirrors allows as well. Events do not contain tokens, scripts, secrets, or file contents.

## What this does not do

- Loopback TCP is not encrypted. Do not publish the port or tunnel the socket.
- This is not an application sandbox. A process you start with a broad capability set can use those capabilities.
- Stdio MCP trusts the user who launched it. Pass `--untrusted` or an explicit `--capabilities` list for a narrower session, and pass `--root` whenever the agent should stay in one directory.
- A reply that exceeds 8 MiB is replaced with an error after the tool may have finished.
- The desktop JavaScript preference remains on unless the user turns it off. Only automation sessions default to off.

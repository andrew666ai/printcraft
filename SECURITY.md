# Security

PrintCraft is a local PDF application for one person. This note covers the desktop control channel, MCP, document JavaScript, and link opens. It is not a hosted service, and it does not add accounts, roles, or an audit pipeline.

## Reporting

Contact the repository owner privately with the version, what you ran, and what happened. Do not include bearer tokens, document contents, or a public exploit.

## Control channel

`printcraft --control <file>` listens on `127.0.0.1` only, on a random port. The listener is not started unless that flag is set. The first line on each connection must be:

```json
{"jsonrpc":"2.0","id":1,"method":"auth","params":{"token":"<64 hex characters>"}}
```

Methods are not dispatched until that handshake succeeds. A missing or wrong token closes the connection with `authentication required` and does not run the method. The token is 256 bits. Comparison does not stop at the first mismatching byte, and hex digits match in either case.

Provide it with one of:

- `--control-token-file <path>` or `PRINTCRAFT_CONTROL_TOKEN_FILE` — a private file. If it does not exist yet, the app creates it (mode `0600` on Unix) and does not print the token.
- `--control-token <64-hex>` or `PRINTCRAFT_CONTROL_TOKEN` — the token itself. Prefer a file: command lines and environments show up to other programs you run.
- neither — the app generates a token and writes it only into `<file>` (mode `0600`), together with the port and pid. It is not printed on stderr.

Do not pass a token and a token file together. Do not commit either file, and do not paste a token into a ticket or chat.

`printcraft-cli ui --control <file>` reads the token from that endpoint file and sends `auth` before the method. Starting the app with no `--control` flag does not listen.

## MCP

Prefer stdio. `printcraft-cli mcp` does not open a TCP port and does not use the control token. The process you started is the trust boundary. There is no MCP-to-TCP bridge.

## Budgets

Each control listener serves at most 16 connections. A request line may be at most 1 MiB. A reply may be at most 8 MiB; a larger reply is replaced with an error that keeps the request id (the edit may already have been applied). Connections use 30-second read and write timeouts. Failures use stable messages: `authentication required`, `connection limit reached`, `request exceeds 1048576 bytes`.

## Document JavaScript

Acrobat JavaScript is **on by default** (Preferences ▸ JavaScript ▸ Enable Acrobat JavaScript). Button scripts, field scripts, and `js_run` then execute code stored in the PDF. Opening a file does not by itself run those scripts; filling fields, clicking a scripted button, the console, and the `js_run` tool do.

For an untrusted PDF, turn JavaScript off before that work:

- in the app: Preferences ▸ JavaScript, clear Enable Acrobat JavaScript;
- in automation, before `js_run` or a fill that should not run scripts: `js_enabled` with `{"enabled": false}`.

With JavaScript off, `js_run` returns an error and field scripts other than Acrobat's built-in AF formatting calls do not run. The preference is remembered with the rest of the app settings. This is a switch, not a sandbox around a script that is allowed to run.

## Links

Links in a PDF, push-button URI actions, and JavaScript `launchURL` are opened only when the URI is `http` or `https` (with a host, and no spaces or control characters). `javascript:`, `file:`, `data:`, and other schemes are refused and do not leave the machine. Help-menu links are https and still open.

## Limitations

An authenticated connection can call the full control surface, including UI input and commands. There is no capability list, session expiry, or security audit log. Loopback TCP is not encrypted — do not tunnel or proxy it. Stdio MCP trusts the local process that spawns it. A process that can read the token file can drive the app. Token files should stay out of the repository and out of shell history.

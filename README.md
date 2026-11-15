# Gatekeeper

Rust reverse proxy that replaces PII and secrets in LLM requests with placeholders, then restores them in responses. Works with Anthropic, OpenAI, and compatible gateways without translating provider schemas.

## Run

```bash
export TARGET_URL=http://localhost:20128
export LISTEN_ADDR=127.0.0.1:8080
mkdir -p -m 700 data
export GATEKEEPER_DB_PATH="$PWD/data/mappings.sqlite3"
cargo run --release
```

Point clients at `http://127.0.0.1:8080`, keeping their provider paths and auth headers. Configure `UPSTREAM_API_KEY` only to override those credentials. See `.env.example`; the binary does not load `.env` automatically.

```bash
docker compose up -d --build
```

Compose includes Ollama and enables durable storage in `gatekeeper_data`. Change `TARGET_URL` for another upstream; container `localhost` means the container itself. `docker compose down -v` deletes stored mappings.

## Storage And Restoration

**Durable mode:** set `GATEKEEPER_DB_PATH` for one global SQLite mapping store, independent of users, conversations, and session IDs.

- Tokens use 48-bit truncated HMAC-SHA256 identifiers derived from a persisted seed, category, and value. Repeated category/value pairs reuse mappings across restarts.
- New mappings commit before forwarding. Storage failures and conflicting new mappings return `503`.
- Known digests restore globally. Unknown complete placeholders get category-shaped decoys derived from a separate seed-derived key, without inserting database rows. The same digest/category produces the same decoy across restarts.
- Unknown placeholder literals supplied in inspected request text are exempt from decoys and echo unchanged. Truncated placeholders may remain unrestored.
- The whole table loads into RAM. Schema v2 databases migrate automatically in place; legacy mappings can retain duplicate originals under different digests. Encrypted schema v1 requires separate migration.

**Request-local mode:** leave `GATEKEEPER_DB_PATH` unset. Only the current request's mappings restore; recognized earlier tokens are wrapped, not resolved through a global plaintext store. Unknown tokens stay unchanged.

**Security:** originals are stored in plaintext. Back up the database, including its seed, before upgrading; use SQLite's backup API or stop the gateway first. Global restoration intentionally has no per-client isolation. Decoys are not authentication or a guarantee that real values cannot be distinguished; they can also alter tool arguments. Unknown lookups do not grow the database, but new redacted values do.

**Optional auth:** set `GATEKEEPER_CLIENT_TOKEN` to require `x-gatekeeper-token` on proxied requests and `/scan`; health checks remain public. The header is stripped upstream. Without this setting, restrict access through your firewall or authenticating reverse proxy. A WAF alone does not necessarily authenticate callers.

## Coverage And Limits

- Scans outbound JSON strings and keys, including nested stringified JSON, plus multipart text/JSON parts.
- Detects names, emails, phones, cards, SSNs, IPs, birth dates, addresses, home-directory prefixes, vendor-prefixed credentials, PEM private keys, and labeled secrets. Detection is heuristic, not exhaustive.
- Custom literals: `GATEKEEPER_REDACT='acme-corp,Project Chimney'`. Match is case-insensitive and whole-word. `GATEKEEPER_REDACT_IDENTITY=user,host` adds this machine's identity, excluding generic names.
- Preserves opaque `encrypted_content` and recognized base64 media. No OCR or decoded-media inspection. Non-JSON request bodies outside multipart pass without fresh PII scanning.
- The tool guard withholds matched results from reads of `.env`, `*.pem`, `*.key`, and copies traced through request history. Writes, `.env.example`, other `.env.*` variants, and `.pub` remain allowed. Unresolved shell expressions and unmatched results limit coverage.
- Restores JSON, SSE, NDJSON, text, and WebSocket turns, including supported split-token forms. Streams buffer fragments as needed, not entire turns. Responses are not scanned for new PII.
- Binary and compressed responses pass through without restoration. Paths, queries, and upstream status codes are preserved; redirects are not followed and requests are not retried.
- WebSockets track `response.create` turns, optionally separated by `stream_id`, with at most 64 queued turns. PII-bearing control messages outside `response.create` are rejected.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `TARGET_URL` | `http://127.0.0.1:11434` | Upstream base URL |
| `LISTEN_ADDR` | `0.0.0.0:8080` | Bind address |
| `UPSTREAM_API_KEY` | unset | Override upstream credentials; falls back to `ANTHROPIC_API_KEY` |
| `UPSTREAM_AUTH_HEADER` | `x-api-key` | Use `authorization` and a `Bearer ` value when required |
| `GATEKEEPER_DB_PATH` | unset | Global database; parent directory must exist |
| `GATEKEEPER_CLIENT_TOKEN` | unset | Optional auth; 32+ printable ASCII characters without whitespace |
| `GATEKEEPER_MAX_BODY_BYTES` | `10485760` | Request and buffered-response limits |
| `GATEKEEPER_REDACT` | unset | Comma-separated custom literals |
| `GATEKEEPER_REDACT_IDENTITY` | unset | `user`, `host`, or both |
| `RUST_LOG` | `info` | Logging filter |

Local endpoints: `GET /health` and `/healthz` return `{"status":"ok"}`. `POST /scan` accepts `{"text":"..."}` and returns matches and anonymized data; it does not save durable mappings. Other routes proxy upstream.

## Development

```bash
cargo fmt --all -- --check
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Additional checks: `cargo bench --bench detector` and `python3 tests/live_compatibility.py --self-test`. See the script's `--help` for live-provider checks.

Inspired by AgentVeil; now an independent project.

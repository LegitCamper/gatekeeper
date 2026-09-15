# Gatekeeper

Gatekeeper is a Rust/Axum reverse proxy that removes sensitive values before LLM API requests reach an upstream provider and restores those values in that request's response. It is a core reimplementation of AgentVeil with no external state service.

## Core behavior

- Detects and tokenizes common PII and secrets in JSON request strings.
- Handles bare 10- and 11-digit, leading-`+`, dashed/dotted/parenthesized, international, and Vietnamese phone formats. Placeholder numbers such as `000-000-0000` are redacted too, so an undialable number in a prompt is still removed.
- Detects person names from a ~19k-entry multi-origin given-name dictionary, plus any capitalized pair after a trigger word (`contact`, `cc:`, `regards,`, `Mr.`, `my name is`). Entries colliding with ordinary English words are excluded, and calendar/direction words are denied, so capitalized technical prose ("New York", "Redis Cluster", "Docker Compose") is left intact.
- Redacts outbound requests only. Response text is never scanned, so a name, number, or address the model invents reaches the client exactly as written.
- Denies outbound tool calls that read `.env`, `.pem`, or `.key` files, so private configuration and key material cannot be handed to a provider. Writes and `.env.example` are unaffected. See [`.env` read guard](#env-read-guard).
- Restores tokens in JSON, Server-Sent Event, and other streamed responses, including tokens split across chunks. Restoration keys on the request-local 12-hex digest, so common model changes to token prefixes, brackets, separators, or hex case still restore the original value.
- Proxies provider headers and payloads without translating Anthropic/OpenAI schemas.
- Never requires Redis or another external state service.

Token mappings are scoped to the request that created them: they live for that request's response and are dropped when it ends. Restoration recognizes the digest even when the model changes or removes token decoration, but only digests owned by that request can resolve. A token or digest from another request stays opaque, so one client's values can never be spliced into another's, and unrelated model output passes through untouched. Because the client receives restored text and sends it back on the next turn, multi-turn conversations need no retained state and no session header.

## `.env` read guard

Gatekeeper inspects outbound tool-call invocations and returns `403` for any that
**read** a protected file, so a file's secrets can never ride a request to the
provider:

- Protected: the exact basename `.env`, plus any `.pem` or `.key` file. Add more
  to `PROTECTED_BASENAMES` / `PROTECTED_EXTENSIONS` in `src/toolguard.rs`.
- Not protected: `.env.example`, `.env.local`, any other `.env.*` variant, and
  `.pub` public keys, which are meant to circulate.
- Writes pass. An agent may create or overwrite these files, so the usual
  `cp .env.example .env` setup works. A command that _reads_ a protected file to
  copy or move it elsewhere (`cp .env /tmp/x`) is denied — relocating a secret is
  how the guard would otherwise be stepped around.
- Checked for every tool, not just file tools: structured arguments (`input`,
  `arguments`, `path`, `file_path`) and shell `command` strings both count, and
  unknown tools are denied on a match.
- The guard only reads outbound requests. Responses and tool results are never
  blocked or rewritten, and prose mentioning `.env` outside an invocation is left
  alone. The `403` body names the protected file and nothing else.

## Run

```bash
cp .env.example .env
export TARGET_URL=http://localhost:20128
export UPSTREAM_API_KEY=your-9router-endpoint-key
cargo run --release
```

Gatekeeper is authless: it never checks a client credential. `UPSTREAM_API_KEY` is the credential it presents to the upstream, and it replaces whatever the client sent so a stale client key cannot leak past the proxy. Leave it unset to forward the client's own auth headers unchanged.

### Docker

Images are published to `ghcr.io/legitcamper/gatekeeper`. Pushes to `main` publish `main` and `latest`; tags such as `v1.2.3` also publish `v1.2.3`, `1.2.3`, and `1.2`.

```bash
docker pull ghcr.io/legitcamper/gatekeeper:latest
docker run --rm --env-file .env -p 8080:8080 ghcr.io/legitcamper/gatekeeper:latest
```

For Compose, copy the environment template, set a reachable upstream, then start the example:

```bash
cp .env.example .env
docker compose -f compose.yml up -d
```

Inside a container, `localhost` refers to that container. Set `TARGET_URL` to an upstream Compose service name such as `http://ollama:11434`, or another host reachable from the container. If the GHCR package is private, authenticate first with `docker login ghcr.io`.

The default listen address is `0.0.0.0:8080`. Send provider requests to Gatekeeper using the same path and headers you would send upstream:

```bash
curl http://127.0.0.1:8080/v1/messages \
  -H 'content-type: application/json' \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H 'anthropic-version: 2023-06-01' \
  -H 'x-request-id: example-request' \
  -d '{
    "model": "claude-opus-5",
    "max_tokens": 256,
    "messages": [{"role":"user","content":"Email Alice Johnson at alice@example.com or +1 (415) 555-2671"}]
  }'
```

No session header is required: restoration is scoped to the request itself. Use any request ID header when upstream observability needs correlation; it does not affect token restoration.

## Local endpoints

- `GET /health` and `GET /healthz` return `{"status":"ok"}`.
- `POST /scan` accepts `{"text":"..."}` and returns detected values plus an anonymized form.
- Every other route is forwarded to `TARGET_URL`, preserving the incoming path and query.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TARGET_URL` | `http://127.0.0.1:11434` | Upstream provider base URL |
| `LISTEN_ADDR` | `0.0.0.0:8080` | TCP listen address |
| `UPSTREAM_API_KEY` | unset | Upstream credential, injected in place of the client's. Falls back to `ANTHROPIC_API_KEY` |
| `UPSTREAM_AUTH_HEADER` | `x-api-key` | Header carrying it. Use `authorization` for Bearer gateways and include the `Bearer ` prefix in the value |
| `GATEKEEPER_MAX_BODY_BYTES` | `10485760` | Maximum buffered request/JSON response body |
| `RUST_LOG` | `info` | Tracing filter |

## Development

```bash
cargo fmt --all -- --check
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo bench --bench detector
```

## Deferred AgentVeil parity

This first release focuses on the requested high-throughput PII proxy. API-key administration, role-based masking, rate limiting, multi-provider routing/fallback, prompt-injection guardrails, webhooks, compliance/auditing, media OCR, CLI commands, and SDK packages remain follow-up work.

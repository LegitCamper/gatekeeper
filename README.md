# Gatekeeper

Gatekeeper is a Rust/Axum reverse proxy that removes sensitive values before LLM API requests reach an upstream provider and restores those values in responses. It is a core reimplementation of AgentVeil designed around a bounded, process-local memory vault instead of Redis.

## Core behavior

- Detects and tokenizes common PII and secrets in JSON request strings.
- Handles bare 10- and 11-digit, leading-`+`, dashed/dotted/parenthesized, international, and Vietnamese phone formats. Placeholder numbers such as `000-000-0000` are redacted too, so an undialable number in a prompt is still removed.
- Detects person names from a ~19k-entry multi-origin given-name dictionary, plus any capitalized pair after a trigger word (`contact`, `cc:`, `regards,`, `Mr.`, `my name is`). Entries colliding with ordinary English words are excluded, and calendar/direction words are denied, so capitalized technical prose ("New York", "Redis Cluster", "Docker Compose") is left intact.
- Stores token mappings in one concurrent bounded global TTL vault.
- Restores tokens in JSON and Server-Sent Event responses.
- Proxies provider headers and payloads without translating Anthropic/OpenAI schemas.
- Never requires Redis or another external state service.

Mappings live in one process-local global vault. Any request can resolve a known token; tokens remain opaque and are hard to guess without the token itself. Mappings expire after the configured TTL (default 30 minutes), refreshed whenever stored or read. Multi-replica deployments need a shared vault outside this core release's scope.

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
docker compose -f compose.example.yml up -d
```

Inside a container, `localhost` refers to that container. Set `TARGET_URL` to an upstream Compose service name such as `http://ollama:11434`, or another host reachable from the container. If the GHCR package is private, authenticate first with `docker login ghcr.io`. Run one Gatekeeper replica unless a shared vault is added because mappings live only in process memory.

The default listen address is `0.0.0.0:8080`. Send provider requests to Gatekeeper using the same path and headers you would send upstream:

```bash
curl http://[IP_111]:8080/v1/messages \
  -H 'content-type: application/json' \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H 'anthropic-version: [DOB_1327]' \
  -H 'x-request-id: example-request' \
  -d '{
    "model": "claude-opus-5",
    "max_tokens": 256,
    "messages": [{"role":"user","content":"Email Alice Johnson at [EMAIL_559] or +1 (415) 555-2671"}]
  }'
```

Mappings are global, so no session header is required. Use any request ID header when upstream observability needs correlation; it does not affect token restoration.

## Local endpoints

- `GET /health` and `GET /healthz` return `{"status":"ok"}`.
- `POST /scan` accepts `{"text":"..."}` and returns detected values plus an anonymized form.
- Every other route is forwarded to `TARGET_URL`, preserving the incoming path and query.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TARGET_URL` | `http://[IP_775]:11434` | Upstream provider base URL |
| `LISTEN_ADDR` | `0.0.0.0:8080` | TCP listen address |
| `UPSTREAM_API_KEY` | unset | Upstream credential, injected in place of the client's. Falls back to `ANTHROPIC_API_KEY` |
| `UPSTREAM_AUTH_HEADER` | `x-api-key` | Header carrying it. Use `authorization` for Bearer gateways and include the `Bearer ` prefix in the value |
| `GATEKEEPER_VAULT_TTL_SECS` | `1800` | Mapping lifetime, refreshed when storing |
| `GATEKEEPER_MAX_SESSIONS` | `10000` | Maximum live sessions |
| `GATEKEEPER_MAX_ENTRIES` | `100000` | Maximum global token mappings |
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

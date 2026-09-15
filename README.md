# Gatekeeper

Gatekeeper is a Rust/Axum reverse proxy that removes sensitive values before LLM API requests reach an upstream provider and restores those values in that request's response.

## Core behavior

- Detects and tokenizes common PII and secrets in JSON request strings. See [Secret coverage](#secret-coverage) for the key and credential formats recognized.
- Handles bare 10- and 11-digit, leading-`+`, dashed/dotted/parenthesized, international, and Vietnamese phone formats. Placeholder numbers such as `000-000-0000` are redacted too, so an undialable number in a prompt is still removed.
- Detects person names through two routes. In ordinary text, a ~19k-entry multi-origin given-name dictionary requires a following capitalized surname; a bare first name is intentionally insufficient. Explicit identity contexts (`my name is`, `name:`, `Mr.`, `Mrs.`, `Ms.`, `Dr.`) accept one to three words, while general person contexts (`attn`, `cc`, `contact`, `patient`, `regards`, `signed`, `sincerely`) accept multi-word names outside the dictionary. Contextual pairs may be lowercase or all caps. Unicode letters, hyphenated names, and common surname particles are supported. Selected common-word, calendar, direction, geographic, and known-phrase deny lists reduce false positives such as "New York", "Redis Cluster", and "Docker Compose"; they do not guarantee that every ambiguous English name is excluded.
- Redacts outbound requests only. Response text is never scanned, so a name, number, or address the model invents reaches the client exactly as written.
- Redacts home-directory paths down to the account name: `/home/<user>`, `/var/home/<user>`, and `/Users/<user>` become one `PATH` token, so the username goes and the rest of the path (`/projects/gatekeeper/src`) stays readable for the model and restorable for the client.
- Redacts whatever you list in `GATEKEEPER_REDACT`, plus optionally this machine's login and host name — see [Custom redaction](#custom-redaction).
- Withholds the result of outbound tool calls that read `.env`, `.pem`, or `.key` files, so private configuration and key material cannot be handed to a provider — while forwarding the request, so the agent keeps working. Writes and `.env.example` are unaffected. See [`.env` read guard](#env-read-guard).
- Restores tokens in JSON, Server-Sent Event, and other streamed responses, including tokens split across chunks. Restoration keys on the request-local 12-hex digest, so common model changes to token prefixes, brackets, separators, or hex case still restore the original value.
- Supports Anthropic and OpenAI wire protocols without translating schemas. Every non-local route keeps its incoming path and query when forwarded to the configured upstream base path, apart from the dot-segment collapsing that any conforming URL parser performs. Upstream redirects are returned to the caller instead of followed inside Gatekeeper.
- Requests that carry no body are forwarded untouched, so provider endpoints that only read — `GET /v1/models`, `/api/tags`, `/api/version` — need no allowance list and see exactly what the caller sent. SDKs put `content-type: application/json` on those calls too, which does not make an absent body malformed. Inspection starts where a body exists.
- Never requires Redis or another external state service.

Token mappings are scoped to the request that created them: they live for that request's response and are dropped when it ends. Restoration recognizes the digest even when the model changes or removes token decoration, but only digests owned by that request can resolve. A token or digest from another request stays opaque, so one client's values can never be spliced into another's, and unrelated model output passes through untouched. Because the client receives restored text and sends it back on the next turn, multi-turn conversations need no retained state and no session header.

## Secret coverage

Keys and credentials are found by their own shape, wherever they appear —
a prompt, a pasted config, a file the agent read. This is independent of the
[`.env` read guard](#env-read-guard), which works on file names: a key in
`notes.txt` or a heredoc is caught here even though that file is unprotected.

**Vendor-prefixed keys.** Recognized on prefix and length, so no label is
needed:

| Vendor | Forms |
| --- | --- |
| Anthropic / OpenAI | `sk-ant-…`, `sk-…` |
| AWS | `AKIA`, `ASIA`, `AGPA`, `AIDA`, `AROA`, `ANPA`, `ANVA` + 16 |
| GitHub | `ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`, `github_pat_` |
| Generic PAT | `pat_` + 20 alphanumerics |
| GitLab | `glpat-` |
| Slack | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` |
| Google | `AIza` + 35 |
| Stripe | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` |
| Shopify | `shpat_`, `shpca_`, `shppa_`, `shpss_` |
| npm | `npm_` + 36 |
| Hugging Face | `hf_` |
| DigitalOcean | `dop_v1_` |
| SendGrid | `SG.…….…` |
| Square | `sq0atp-`, `sq0csp-` |
| Databricks | `dapi` + 32 hex |
| PyPI | `pypi-AgEIcHlwaS5vcmc…` |
| JWT | `eyJ….….…` |

**PEM private keys.** Matched on content, not file name: any
`-----BEGIN … PRIVATE KEY-----` through its matching `-----END-----` is taken
as one value, up to 8 KiB. RSA, EC, OPENSSH, PKCS#8, and unlabeled blocks all
match, so key material in `backup.txt`, `server.pem.bak`, or a shell heredoc is
removed even though those names mean nothing to the file guard. A lone armor
line is matched on its own, so a truncated or quoted block is still caught.

**Labeled secrets.** A password or house-built token has no prefix and no
shape, so the label is what finds it. After `password`, `passwd`, `secret`,
`api_key` / `api-key` / `apikey`, `auth_token`, `access_token`,
`refresh_token`, `client_secret`, `private_key`, or `bearer` — followed by
`:` or `=` — the value is tokenized and the label stays readable.

**AWS secret access keys** need their label too (`aws_secret_access_key = …`).
Forty base64 characters is too ordinary a shape to redact unlabeled.

What this deliberately does not catch:

- Prose. `rotate the password before Friday` has no separator and no value.
- Environment references and placeholders: `api-key: $ANTHROPIC_API_KEY` and
  `api_key: <your-key-here>` name no secret, so both pass through.
- Type annotations: `private_key: Option<String>` is code, not a credential.
  A bare PascalCase type wider than eight characters (`client_secret:
  SecretString`) is still tokenized — it round-trips intact, so the cost is
  model readability rather than correctness.
- Unlabeled high-entropy strings. A bare 32-character value with no prefix and
  no label is indistinguishable from a hash, an ID, or a commit SHA.

Everything here lands in the `API_KEY` token class and round-trips like any
other value: the provider sees a token, the client sees the original bytes.

## `.env` read guard

Gatekeeper inspects outbound tool-call invocations and **withholds the result** of
any that **read** a protected file, so a file's secrets can never ride a request to
the provider:

- Protected: the exact basename `.env`, plus any `.pem` or `.key` file. Add more
  to `PROTECTED_BASENAMES` / `PROTECTED_EXTENSIONS` in `src/toolguard.rs`.
- Not protected: `.env.example`, `.env.local`, any other `.env.*` variant, and
  `.pub` public keys, which are meant to circulate.
- Writes pass. An agent may create or overwrite these files, so the usual
  `cp .env.example .env` setup works.
- **A copy of a protected file stays protected.** `cp .env /tmp/local.env` is a
  legitimate tool call and is forwarded untouched — but the guard records where the
  secret landed and withholds reads of *that* path too, so `cat /tmp/local.env` on a
  later turn is stripped like the original. Copy-of-a-copy chains resolve, since
  every hop is in the request history.
- Checked for every tool, not just file tools: structured arguments (`input`,
  `arguments`, `path`, `file_path`) and shell `command` strings both count.
- The request is forwarded, not refused. A read has already run on your machine by
  the time its contents ride back outbound, and clients resend conversation history
  every turn — so a refusal stops the agent *and* every later turn of that session
  without un-reading the file. Withholding the payload blocks the one thing that
  matters (the provider seeing the file) and leaves the agent working. The result
  becomes:

  ```text
  [gatekeeper withheld the contents of .env. Do not retry the read or reach for
  another tool: this proxy never forwards them to the model provider. Ask the
  user for the value you need.]
  ```

  The wording tells the model to ask rather than route around, which is what a
  silent blank would invite.
- Correlated by call id (`tool_use_id`, `tool_call_id`, `call_id`), so only the
  result answering that read is blanked: unrelated tool output, prose mentioning
  `.env`, and the read invocation itself all survive untouched. A read whose result
  is not in the body cannot be stripped and is logged as `unpaired` at `warn` level,
  where PII redaction is the remaining net.
- Shell expansions are resolved, not refused. `x=n; cat .e${x}v` names `.env` once
  the command's own `x=n` is substituted, so it is caught. A value inherited from
  the parent shell (`${HOME}`, `$()`) cannot be resolved from the request alone;
  those spellings are **not** blocked, and PII redaction is the net. The earlier
  fail-closed rule that blocked *any* shell call containing `$(`, `${`, or a
  backtick was removed — it stopped `echo "built $(date)"` and similar ordinary
  commands, which is the over-blocking the forward-only design is meant to avoid.
- The guard reads outbound requests only. Provider responses are never blocked or
  rewritten.

Anything Gatekeeper does reject is still shaped like a provider error, so a client
or a model relaying the failure shows a reason instead of an opaque transport error:

```json
{
  "type": "error",
  "error": {
    "type": "gateway_error",
    "message": "upstream request failed: connection refused"
  }
}
```

`error.type` is `gatekeeper_security_error` when a size limit protects redaction and
`gateway_error` for everything else Gatekeeper rejects itself (oversized body,
unreachable upstream, undecodable upstream response). Those cannot be answered with a
pass-through: an oversized body cannot be parsed, so it cannot be redacted, and a
transport failure has no upstream answer to forward. They are `413`/`502`, not policy
denials — no security control on the agent path throws any more.

## Custom redaction

```bash
# Literal values, comma-separated, matched case-insensitively and whole-word.
export GATEKEEPER_REDACT='acme-corp,Project Chimney'
# Also redact this machine's login name and host name, read at startup so they
# never have to be written into an env file. `user`, `host`, or both.
export GATEKEEPER_REDACT_IDENTITY=user,host
```

Both land in the same `CUSTOM` token class and round-trip like any other value.
Limits worth knowing:

- Values are literals, not regexes: `12.34` blanks only that string, never every
  two-digit-dot-two-digit number. Pattern support is the obvious next step if a
  case for it shows up.
- A value with a comma cannot be expressed, and one-character values are dropped
  as noise.
- `GATEKEEPER_REDACT_IDENTITY` skips names that are ordinary words (`root`,
  `admin`, `node`, `localhost`, …) and logs why — blanking those would mangle more
  text than it hides. Force one by listing it in `GATEKEEPER_REDACT`.
- Home-directory paths need no configuration at all: `/home/<user>`,
  `/var/home/<user>`, and `/Users/<user>` are always tokenized. `/root` is not,
  since it names a standard account rather than a person.

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

### Provider transparency

Gatekeeper is endpoint- and schema-neutral. Anthropic `/v1/messages`, OpenAI `/v1/chat/completions` or `/v1/responses`, and other provider routes use the same incoming path and query upstream. A path already present in `TARGET_URL` is retained as a prefix, and a query on it is kept as an upstream parameter: with `TARGET_URL=https://gateway.example/api?api-version=2024-02-01`, incoming `/v1/messages?beta=1` goes to `/api/v1/messages?beta=1&api-version=2024-02-01`. Configure `TARGET_URL` as the canonical provider or gateway base URL; Gatekeeper does not discover or rewrite provider endpoints.

Request methods, provider headers, response status, response headers, JSON structure, SSE framing, NDJSON records, and stream mode pass without Anthropic/OpenAI schema translation. Gatekeeper does not retry requests or convert a streaming request into a non-streaming one. Upstream redirects are forwarded with their `3xx` status and `Location`; Gatekeeper does not follow them and hide the redirect behind a later response.

Responses are not validated against provider schemas or scanned for new sensitive values. Only placeholders created while redacting that request are restored in its response. Parsed JSON may be re-encoded, changing insignificant whitespace or object-key order without changing its data structure. If a provider or intermediate gateway directly returns valid JSON with HTTP `200` but the wrong provider schema, Gatekeeper forwards it; diagnose that upstream response and its request-ID headers. Malformed JSON that is valid UTF-8 is likewise forwarded with its upstream status after request-local restoration. Gatekeeper asks upstream for `accept-encoding: identity` so responses arrive as plain text; an upstream that ignores that gets its compressed body forwarded byte for byte with its `Content-Encoding` and a `warn` log, unrestored, because rewriting compressed bytes would corrupt them for the client. Undecodable bytes with no declared encoding cannot be restored at all and produce a Gatekeeper `502`.

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
| `GATEKEEPER_REDACT` | unset | Comma-separated literal values to redact as `CUSTOM`, matched case-insensitively and whole-word |
| `GATEKEEPER_REDACT_IDENTITY` | unset | `user`, `host`, or both: redact this machine's login name and hostname, read at startup |
| `RUST_LOG` | `info` | Tracing filter |

## Development

```bash
cargo fmt --all -- --check
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo bench --bench detector
```

## Inspiration

Gatekeeper was inspired by AgentVeil but has since evolved into an independent project.

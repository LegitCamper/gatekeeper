# Gatekeeper

Gatekeeper is a Rust/Axum reverse proxy that removes sensitive values before LLM API requests reach an upstream provider. By default, restoration is request-local. Optional plaintext SQLite storage restores mappings across requests and restarts, scoped to an authenticated owner's conversation. The Compose setup enables this durable mode.

## Durable conversation storage

Set `GATEKEEPER_DB_PATH` and `GATEKEEPER_CLIENT_TOKEN` to enable persistence. No encryption key is required. Without a database path, the request-local behavior described below remains unchanged.

Each gateway instance serves one configured `GATEKEEPER_OWNER_ID` (default `local`) authenticated by its client token. Every proxied request must supply `x-gatekeeper-token` and a stable conversation ID in `x-gatekeeper-conversation-id`, `thread-id`, or `thread_id`. IDs accept 1-256 ASCII letters, digits, dots, underscores, or hyphens and are case-sensitive. If multiple identity headers or repeated values are present, they must all match exactly; none overrides another. Missing, invalid, or conflicting IDs stop the request before upstream forwarding. Both Gatekeeper headers are stripped before forwarding upstream; provider authorization headers retain their existing behavior.

The client must save the ID with its conversation and send it again when reopening that conversation, including after a gateway restart. Use an existing stable thread ID, or generate an ID once when creating the conversation and persist it in client metadata. Use different IDs for independent conversations; a single static header for every chat combines their mappings. Gatekeeper does not infer identity from message text, IP addresses, API keys, request IDs, session IDs, or connection IDs, and does not mint a new ID when one is missing. A client that cannot send a stable per-conversation header needs an adapter before using durable mode. Switching between supported header names preserves identity when the value is unchanged.

Storage uses values, conversations, and bindings tables, plus one metadata row holding a randomly generated identifier seed. Identical original bytes are stored once per owner as plaintext; conversations reference the same value using different placeholders. Repeated use in one conversation reuses its binding. A full HMAC-SHA256 fingerprint deduplicates values; the database seed keeps fingerprints and scoped placeholders stable across restarts without an external key. Collision checks fail rather than overwrite. The seed is not encryption and is not an at-rest security boundary. Missing seed metadata fails startup rather than silently replacing it.

**Database readers can see original values and their conversation associations.** Neither a conversation ID nor a placeholder is authentication; the client token authorizes access to this owner's conversations. Upstream AI API access is not a substitute for gateway authentication. Restrict filesystem and backup access even though storage intentionally remains plaintext.

SQLite uses WAL, foreign keys, and `synchronous=FULL`. Mappings commit before a request reaches the provider; storage errors stop forwarding. The plaintext hot cache has a 1 MiB accounting budget; eviction never deletes disk mappings. Each request loads a bounded conversation snapshot (at most 10,000 bindings and `GATEKEEPER_MAX_BODY_BYTES` of accounted mapping data). Exceeding either limit fails closed rather than silently dropping old mappings. Concurrent active requests hold their own snapshots in addition to the shared cache.

**Durable mode buffers each complete HTTP response or WebSocket turn before releasing it.** JSON, SSE, NDJSON, text, and JSON WebSocket messages retain their protocol framing, but tokens no longer stream to the client as they arrive. Unresolved canonical placeholders, malformed JSON/stream data, incomplete SSE/WebSocket turns, unsupported binary/compressed HTTP responses, oversized output, or strings encoded beyond four JSON parsing levels produce a gateway error. This guard recognizes canonical placeholder syntax, not arbitrary model-invented variants or bare unknown digests. Opaque reasoning and media fields are never rewritten by restoration; the guard still checks serialized text for canonical placeholders so a field name cannot bypass validation. Encoded media is not decoded or scanned for PII. Legacy mode keeps its existing streaming and pass-through behavior.

WebSocket authentication and the conversation ID are fixed at handshake. Each named `stream_id` gets a stable, separate storage scope; the unnamed lane uses the handshake conversation ID. Use separate conversations for independent work. Control events without a response identity cannot introduce redacted values. Durable sockets require JSON messages; non-JSON binary messages are rejected. Deleting a handshake conversation also removes its named lane scopes.

Delete one conversation's mappings with `DELETE /gatekeeper/conversation`, supplying the same authentication and conversation headers. Values shared with other conversations remain; unreferenced values are removed. Deletion affects future loads, not snapshots already held by in-flight requests, so stop active work first. Logical deletion is not forensic erasure of WAL files, snapshots, or backups. `/health` and `/healthz` remain public; `/scan` requires client authentication in durable mode and remains a request-local diagnostic, not a durable token minting API.

Back up the complete database, including its identifier seed, using SQLite's backup API or after stopping the gateway; do not copy only the main file while WAL writes are active. Losing the database loses restoration. Changing the owner ID changes the namespace. Client tokens can rotate without changing stored mappings. Use TLS or a trusted local connection for the client token; Compose binds the gateway to loopback by default. This is a single-owner gateway, not a multi-user authentication service. The earlier experimental encrypted schema (v1) is rejected without rewriting its contents; migration is not automatic. Preserve that database and its old key if it contains mappings you still need.

Old request-local tokens that have already lost their originals cannot be migrated automatically. Start a fresh conversation and reread the original files when moving an affected conversation to durable mode. Saving fingerprints alone would not recover those values.

### Compose setup

Create a private `.env` file, or add the client token to your existing file without overwriting its other settings:

```bash
umask 077
touch .env
chmod 600 .env
openssl rand -hex 32  # copy into GATEKEEPER_CLIENT_TOKEN
docker compose -f compose.yml up -d --build
```

Compose keeps `mappings.sqlite3`, its WAL, and shared-memory file together in the `gatekeeper_data` named volume, writable by the nonroot container user. Normal container replacement preserves mappings. `docker compose down -v` deletes that volume and its mappings. SQLite is bundled into the binary; no database service is required. Retain the volume after upgrades and restarts. A missing client token makes Compose fail configuration rather than run with insecure defaults.

Configure your client's HTTP headers with the client token and a stable conversation ID; never place credentials in the prompt. For a manual test, with the token exported in your shell:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "x-gatekeeper-token: $GATEKEEPER_CLIENT_TOKEN" \
  -H 'x-gatekeeper-conversation-id: example-thread' \
  -H 'content-type: application/json' \
  --data '{"model":"your-model","messages":[{"role":"user","content":"Hello"}]}'
```

To run locally with persistence, create a private data directory, set `GATEKEEPER_DB_PATH` to its database filename, and export the storage key and client token before starting Gatekeeper. The process does not load `.env` automatically.

## Request-local mode

```
   agent / SDK             Gatekeeper :8080            upstream provider
   any LLM client      authless, no sessions, 1 hop    Anthropic / OpenAI / ...

     |                        |                             |
     | --- REQUEST ---------> | ---- tokens, no PII ----->  |
     |                        |                             |
     | < -- RESPONSE -------- | < -- originals restored --  |
     |                        |                             |

 ROUTE
   /health, /healthz .......... {"status":"ok"}  (local)
   /scan ...................... {matches, anonymized}  (local)
   anything else .............. proxy()

 proxy() - outbound, in order:

   1  body > GATEKEEPER_MAX_BODY_BYTES ................. 413
   2  no body ................... forward untouched
      (GET /v1/models, /api/tags, DELETE: no allowlist,
       no rewriting - SDKs send a JSON content-type on
       these too, and an absent body is not malformed)
   3  upgrade: websocket ........ WebSocket bridge (below)
   4  JSON parse
        ok ..................... step 5
        claims JSON, broken .... 400
        multipart/form-data .... text + JSON/NDJSON parts scanned,
          binary parts preserved, malformed part 400
        not JSON (binary, form, prose) ... passthrough, step 9
   5  tool guard - WITHHOLD, never refuse
        read of .env / *.pem / *.key ... result replaced by
          a "ask the user" notice, the call still forwarded
        cp .env /tmp/x ... legitimate, but the copy is tracked:
          a later read of that path is blanked too
   6  detector - PII + secrets -> tokens
        API_KEY EMAIL CARD SSN IP DOB PHONE ADDRESS NAME
        PATH CUSTOM
        "[EMAIL_a1b2c3d4e5f6]"  <-  a real address, a phone, a name
        fingerprints are cached process-wide, so a token the client
          echoes from an earlier turn is recognized and wrapped in a
          fresh request-local token before it reaches the provider
          (the registry never stores or restores plaintext)
   7  headers - hop-by-hop dropped, client accept-encoding
      dropped, upstream asked for identity
   8  auth - UPSTREAM_API_KEY replaces the client credential;
      unset, the client's own header is forwarded
   9  same path + query onto TARGET_URL - no schema
      translation, no retries, redirects not followed

 upstream - RESPONSE back:

  10  status + headers forwarded; a 3xx handed to the caller
  11  restore only this request's mappings
        JSON | SSE | NDJSON | plain text | WebSocket frames
        token split across chunks -> carried, then stitched
        earlier tokens recognized inbound -> wrapped, not resolved
        model-invented text and foreign tokens -> left alone
        responses are never scanned for new secrets
  12  no tokens ............ byte-for-byte passthrough
      binary content-type .. byte-for-byte passthrough
      upstream compressed .. warn, bytes handed back as-is
      undecodable body ..... 502

 what can make Gatekeeper answer by itself:
   413  oversized request, or oversized JSON response whose
        tokens could not be restored
   400  body declares JSON but does not parse
   502  unreachable upstream, or undecodable upstream body
   no policy denial exists: a protected read is stripped,
   not rejected
```

## Core behavior

- Detects and tokenizes common PII and secrets in JSON request strings and object keys, including recursively encoded JSON objects and arrays inside string values. See [Secret coverage](#secret-coverage) for the key and credential formats recognized.
- Preserves `encrypted_content` JSON fields byte for byte. Responses API reasoning items use these as opaque replay values, so scanning or rewriting them would invalidate the ciphertext.
- Preserves base64 media in image URLs, file data URLs, Anthropic base64 sources, Gemini inline data, and OpenAI input audio, including tool results and stringified JSON. Text beside these payloads is still redacted. Encoded media is forwarded unchanged; Gatekeeper does not inspect its decoded contents or perform OCR.
- Handles bare 10- and 11-digit, leading-`+`, dashed/dotted/parenthesized, international, and Vietnamese phone formats. Placeholder numbers such as `000-000-0000` are redacted too, so an undialable number in a prompt is still removed.
- Detects person names through two routes. In ordinary text, a ~19k-entry multi-origin given-name dictionary requires a following capitalized surname; a bare first name is intentionally insufficient. Explicit identity contexts (`my name is`, `name:`, `Mr.`, `Mrs.`, `Ms.`, `Dr.`) accept one to three words, while general person contexts (`attn`, `cc`, `contact`, `patient`, `regards`, `signed`, `sincerely`) accept multi-word names outside the dictionary. Contextual pairs may be lowercase or all caps. Unicode letters, hyphenated names, and common surname particles are supported. Selected common-word, calendar, direction, geographic, and known-phrase deny lists reduce false positives such as "New York", "Redis Cluster", and "Docker Compose"; they do not guarantee that every ambiguous English name is excluded.
- Redacts outbound requests only. Response text is never scanned, so a name, number, or address the model invents reaches the client exactly as written.
- Redacts home-directory paths down to the account name: `/home/<user>`, `/var/home/<user>`, and `/Users/<user>` become one `PATH` token, so the username goes and the rest of the path (`/projects/gatekeeper/src`) stays readable for the model and restorable for the client.
- Redacts whatever you list in `GATEKEEPER_REDACT`, plus optionally this machine's login and host name — see [Custom redaction](#custom-redaction).
- Withholds the result of outbound tool calls that read `.env`, `.pem`, or `.key` files, so private configuration and key material cannot be handed to a provider — while forwarding the request, so the agent keeps working. Writes and `.env.example` are unaffected. See [`.env` read guard](#env-read-guard).
- Restores tokens in JSON, Server-Sent Event, and other streamed responses, including tokens split across chunks. Restoration resolves only request-local mappings, so common model changes to token prefixes, brackets, separators, or hex case restore only when the digest belongs to that request.
- Supports Anthropic and OpenAI wire protocols without translating schemas. Every non-local route keeps its incoming path and query when forwarded to the configured upstream base path, apart from the dot-segment collapsing that any conforming URL parser performs. Upstream redirects are returned to the caller instead of followed inside Gatekeeper.
- Requests that carry no body are forwarded untouched, so provider endpoints that only read — `GET /v1/models`, `/api/tags`, `/api/version` — need no allowance list and see exactly what the caller sent. SDKs put `content-type: application/json` on those calls too, which does not make an absent body malformed. Inspection starts where a body exists.
- Never requires Redis or another external state service.

Plaintext mappings are request-local and are dropped when the response ends. A process-global registry retains only keyed fingerprints of previously issued tokens, never their original values. When a client sends an earlier token `T1` in a later request, Gatekeeper recognizes its fingerprint and replaces it with a fresh request-local token `T2` upstream. If the provider echoes `T2`, the client receives exactly `T1`, not the secret that originally produced `T1`. If the provider independently replays `T1`, it remains `T1` because no global plaintext mapping exists.

This strict wrapping preserves opaque placeholders across conversation turns without retaining plaintext globally or allowing one request to recover another request's secret. Registry entries expire after 30 minutes without a full-token hit and cap at 10,000 entries, evicting the colder half under pressure. Unknown and colliding fingerprints stay opaque. Restarting Gatekeeper rotates the keyed fingerprint seed and clears the registry. No session header is required.

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

Request-local mode is authless. Durable mode requires its separate Gatekeeper client token. `UPSTREAM_API_KEY` is the credential presented to the upstream, replacing whatever the client sent so a stale client key cannot leak past the proxy. Leave it unset to forward the client's own provider auth headers unchanged.

### Docker

Images are published to `ghcr.io/legitcamper/gatekeeper`. Pushes to `main` publish `main` and `latest`; tags such as `v1.2.3` also publish `v1.2.3`, `1.2.3`, and `1.2`.

```bash
docker pull ghcr.io/legitcamper/gatekeeper:latest
docker run --rm --env-file .env -p 8080:8080 ghcr.io/legitcamper/gatekeeper:latest
```

For Compose, follow the durable-storage setup above: set both independent secrets in a private `.env` file and configure a reachable upstream before starting the example. Do not overwrite an existing environment file or rotate an existing storage key:

```bash
docker compose -f compose.yml up -d --build
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

In request-local mode, no session header is required: strict wrapping carries opaque tokens across turns without global plaintext restoration. Durable mode additionally requires the Gatekeeper client token and stable conversation identity described above. An ordinary request ID used for observability does not select restoration scope.

### Provider transparency

The response and streaming policies in this section describe request-local mode. Durable mode adds authenticated conversation restoration, bounded response buffering, and fail-closed validation as described above.

Gatekeeper is endpoint- and schema-neutral. Anthropic `/v1/messages`, OpenAI `/v1/chat/completions` or `/v1/responses`, and other provider routes use the same incoming path and query upstream. A path already present in `TARGET_URL` is retained as a prefix, and a query on it is kept as an upstream parameter: with `TARGET_URL=https://gateway.example/api?api-version=2024-02-01`, incoming `/v1/messages?beta=1` goes to `/api/v1/messages?beta=1&api-version=2024-02-01`. Configure `TARGET_URL` as the canonical provider or gateway base URL; Gatekeeper does not discover or rewrite provider endpoints.

Request methods, provider headers, response status, response headers, JSON structure, SSE framing, NDJSON records, and stream mode pass without Anthropic/OpenAI schema translation. Gatekeeper does not retry requests or convert a streaming request into a non-streaming one. Upstream redirects are forwarded with their `3xx` status and `Location`; Gatekeeper does not follow them and hide the redirect behind a later response.

Responses are not validated against provider schemas or scanned for new sensitive values. Only request-local mappings are restored. The process-global registry can recognize an earlier token's keyed fingerprint but holds no plaintext: provider replay of an earlier `T1` remains `T1`, while inbound `T1` is wrapped as a fresh `T2` upstream and an echoed `T2` unwraps to exactly `T1`. A name, number, address, or secret newly introduced by the upstream is never scanned, filtered, or tokenized. A stream event with nothing to restore is forwarded byte for byte, `event:` line, key order, and all; a payload that did receive a value is re-encoded, which can change insignificant whitespace or object-key order without changing its data structure. Provider protocol fields — `type`, `index`, `delta.type`, stop reasons — are never rewritten by restoration. Response status and end-to-end headers remain upstream's; only hop-by-hop headers are removed as HTTP forwarding requires. If a provider or intermediate gateway directly returns valid JSON with HTTP `200` but the wrong provider schema, Gatekeeper forwards it; diagnose that upstream response and its request-ID headers. Malformed JSON that is valid UTF-8 is likewise forwarded with its upstream status after request-local restoration. A fresh non-JSON request body that contains raw PII is passed through unredacted; non-JSON text is inspected only for recognized placeholders that need strict wrapping. Gatekeeper asks upstream for `accept-encoding: identity` so responses arrive as plain text; an upstream that ignores that gets its compressed body forwarded byte for byte with its `Content-Encoding` and a `warn` log, unrestored, because rewriting compressed bytes would corrupt them for the client. Undecodable bytes with no declared encoding cannot be restored at all and produce a Gatekeeper `502`.

### Multipart uploads

`multipart/form-data` bodies are walked part by part instead of being passed through whole. Text parts and parts whose content type or filename marks them as JSON, JSONL, or NDJSON (`.json`, `.jsonl`, `.ndjson`, text suffixes) are redacted with the same detector and tool guard as a JSON body; every other part — images, audio, archives — is forwarded byte for byte. Part headers, names, filenames, and boundary order are preserved, and the reassembled body uses the incoming boundary.

A part Gatekeeper cannot read is refused before it reaches upstream, with a `400` and a `gateway_error`: a malformed boundary, a part with no name, or a `content-transfer-encoding` that would hide text from the detector. Passing those through would mean forwarding unscanned bytes, which is the one failure mode redaction cannot tolerate.

### WebSockets

An incoming request carrying `upgrade: websocket` is bridged to the same path and query on `TARGET_URL`, with `http`/`https` mapped to `ws`/`wss`. Gatekeeper performs the upstream handshake first, so the client's connection is only accepted once upstream agrees; the negotiated `sec-websocket-protocol` is echoed back to the client, and `UPSTREAM_API_KEY` replaces the client credential on the handshake exactly as it does for HTTP. A handshake the upstream rejects comes back as that status with a `gateway_error` body and upstream's own headers (`x-request-id` and friends) intact.

Each `response.create` message opens a turn with its own restorer, so a value redacted in one turn is never restored into another. Turns are tracked per lane: an optional top-level `stream_id` (1–256 characters of `[A-Za-z0-9_.-]`) keeps parallel conversations on one socket independent, is treated as routing metadata rather than model text, and is stripped before the message reaches the detector and re-attached after. Messages with no `stream_id` share the default lane and are answered in order.

Inbound frames are restored per turn with the same stream carry as SSE, so a token split across two deltas is held and stitched. JSON arriving in a binary frame is inspected and sent back as a binary frame; non-JSON binary frames pass through untouched. `ping` is answered in both directions, and a close from either side is propagated with its code and reason after any text still held for stitching is flushed, so no partial token is lost on shutdown.

Limits mirror the HTTP path. `GATEKEEPER_MAX_BODY_BYTES` caps frame and message size, total queued request bytes, and buffered restoration bytes; at most 64 turns may be in flight. Exceeding a limit, sending non-JSON text, or sending an invalid `stream_id` returns a `gateway_error` event on the socket instead of dropping the connection. A PII-bearing message that is not `response.create` is refused the same way: there is no response identity to scope its mappings to, so it cannot be restored safely.

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
| `GATEKEEPER_DB_PATH` | unset | Enables durable storage; parent directory must exist |
| `GATEKEEPER_OWNER_ID` | `local` | Stable owner namespace for this authenticated gateway instance |
| `GATEKEEPER_CLIENT_TOKEN` | unset | Required with storage: separate random client credential, at least 32 printable ASCII characters |
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

### Live provider matrix

`tests/live_compatibility.py` runs an endpoint/tool/image matrix against a real gateway, directly and through a local Gatekeeper, and labels every row `PASS`, `UPSTREAM_QUIRK`, `UPSTREAM_FAILURE`, or `PROXY_FAILURE` so a provider bug is never read as a proxy bug. Stdlib only, no provider URLs or model IDs baked in, and the key is redacted from its output.

```bash
GATEKEEPER_TEST_UPSTREAM=https://gateway.example \
GATEKEEPER_TEST_API_KEY=your-key \
GATEKEEPER_TEST_MODELS=vendor/model-a,vendor/model-b \
python3 tests/live_compatibility.py --protocol responses --protocol chat --checks tool,image,structured
```

`GATEKEEPER_TEST_AUTH_HEADER` picks the credential header (include a `Bearer ` prefix in the key when the gateway wants one), `GATEKEEPER_TEST_PROXY` points at an already-running Gatekeeper instead of spawning one, and `--self-test` exercises the harness against a local fixture server with no network at all. The WebSocket equivalent is `cargo test --test websocket -- --ignored` with `GATEKEEPER_TEST_UPSTREAM` and `GATEKEEPER_TEST_MODELS` set; an HTTP-only gateway answers the upgrade with `404`/`405`/`501` and those rows are skipped rather than failed.


## Inspiration

Gatekeeper was inspired by AgentVeil but has since evolved into an independent project.

//! Tool-call guard: blanks the result of any tool-call invocation that **read**
//! a file holding private key material or environment secrets, so those contents
//! can never ride an outbound request to a provider.
//!
//! The guard looks only at invocation shapes (Anthropic `tool_use` blocks,
//! OpenAI `tool_calls`/`function.arguments`, and anything carrying a `command`
//! argument such as Bash), never at prose, tool *definitions*, or response
//! bodies. Writes are allowed — an agent initializing `.env` from
//! `.env.example` is the intended setup flow — and a read that already ran is
//! answered by withholding its payload rather than by refusing the request, so
//! the agent keeps working and the provider still sees nothing.
//!
//! `ponytail:` shell rules are conservative token heuristics, not a shell parser.
//! Quote, escape, glob, connector, redirection, and same-command `name=value`
//! forms are resolved; a value inherited from the parent shell is not, and neither
//! is an argument built by `$()`. Blocking every expansion instead was rejected:
//! it stopped ordinary work like `echo "built $(date)"`. PII redaction is the net
//! for what the heuristics miss. Upgrade path is a real command parser.

use std::borrow::Cow;

use serde_json::{Value, map::Map};

/// Exact basenames protected from reads. `.env` is matched whole so the
/// `.env.example` / `.env.local` / `.envrc` shapes stay reachable.
const PROTECTED_BASENAMES: &[&str] = &[
    ".env",
    ".git-credentials",
    ".npmrc",
    ".pgpass",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.yaml",
    "secrets.yml",
];

/// Exact path suffixes whose basename alone is too generic to block. Slash form
/// is canonicalized by [`protected_segment`] before comparison.
const PROTECTED_PATH_SUFFIXES: &[(&str, &str)] = &[
    ("/.aws/credentials", "AWS credentials"),
    ("/.kube/config", "Kubernetes config"),
];

/// Extensions protected from reads: a private key is a private key whatever it
/// is called. Public keys (`.pub`) are deliberately absent — they are meant to
/// circulate.
const PROTECTED_EXTENSIONS: &[&str] = &[".pem", ".key"];

/// Structured tools whose whole purpose is writing the file they name.
const WRITE_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

/// Shell commands whose final positional argument is the write destination.
const MOVE_COMMANDS: &[&str] = &["mv", "install", "rename"];

/// Shell commands taking one or more sources plus a final destination.
const COPY_COMMANDS: &[&str] = &["cp"];

/// Shell commands where every argument is a write destination.
const SINK_COMMANDS: &[&str] = &["tee", "truncate"];

/// Redirection operators; the token following one is a write destination.
const REDIRECT: &str = ">";

/// Tokens that end a command segment, so a later command cannot inherit an
/// earlier one's write destination.
const BOUNDARY: &[&str] = &[";", "|", REDIRECT];

/// Returns the first protected basename a tool-call invocation in `value` tries
/// to read, if any.
pub fn protected_file_read(value: &Value) -> Option<&'static str> {
    match value {
        Value::Object(map) => {
            if is_invocation(map) {
                if let Some(hit) = invocation_read(map) {
                    return Some(hit);
                }
            }
            map.values().find_map(protected_file_read)
        }
        Value::Array(values) => values.iter().find_map(protected_file_read),
        _ => None,
    }
}

/// Outcome of [`withhold_protected_reads`], so the caller can log what happened
/// without walking the body a second time.
#[derive(Debug, Default)]
pub struct Withheld {
    /// What was blanked, named by protected basename (`.env`) or, for a copy, by
    /// the path it was copied to.
    pub blanked: Vec<String>,
    /// Protected reads with no pairable result in this body: either the call has
    /// not run yet, or a hand-built body hid the payload where no tool contract
    /// would put it. Nothing was blanked, so PII redaction is the only thing
    /// standing between that body and the provider.
    pub unpaired: Vec<String>,
}

/// A protected read found in a body, with the call id its result answers to when
/// the tool contract carries one.
struct ReadCall {
    id: Option<String>,
    /// What to tell the model was withheld: the basename for a protected file,
    /// the destination path for a copy of one.
    label: String,
}

/// Blanks the payload of every tool result that answers a protected read, in
/// place, and reports what it found.
///
/// Refusing the request instead would be a weaker control and a harsher one: the
/// read has already run on the client's machine by the time its contents ride
/// back outbound, and because clients resend the whole conversation every turn,
/// one refusal fails every later turn of that session as well. Withholding the
/// payload stops the thing that matters — the provider seeing the file — while
/// leaving the agent with an explanation rather than an error to route around.
pub fn withhold_protected_reads(value: &mut Value) -> Withheld {
    let relocated = relocated_paths(value);
    let mut calls = Vec::new();
    collect_reads(value, None, &relocated, &mut calls);

    let mut blanked_ids: Vec<String> = Vec::new();
    let mut blanked: Vec<String> = Vec::new();
    blank_results(value, &calls, &mut blanked_ids, &mut blanked);

    let mut unpaired: Vec<String> = calls
        .iter()
        .filter(|call| {
            !call
                .id
                .as_deref()
                .is_some_and(|id| blanked_ids.iter().any(|blanked| blanked == id))
        })
        .map(|call| call.label.clone())
        .collect();
    for list in [&mut blanked, &mut unpaired] {
        list.sort();
        list.dedup();
    }

    Withheld { blanked, unpaired }
}

fn collect_reads(
    value: &Value,
    enclosing_id: Option<&str>,
    relocated: &[String],
    calls: &mut Vec<ReadCall>,
) {
    match value {
        Value::Object(map) => {
            let id = invocation_id(map).or(enclosing_id);
            if is_invocation(map)
                && let Some(label) = read_label(map, relocated)
                // The OpenAI chat shape nests the arguments one level below the id,
                // so parent and child both surface the same call. Record it once.
                && !calls
                    .iter()
                    .any(|call| call.label == label && call.id.as_deref() == id)
            {
                calls.push(ReadCall {
                    id: id.map(str::to_owned),
                    label,
                });
            }
            map.values()
                .for_each(|value| collect_reads(value, id, relocated, calls));
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_reads(value, enclosing_id, relocated, calls)),
        _ => {}
    }
}

/// What this invocation reads that must not reach the provider, if anything.
fn read_label(map: &Map<String, Value>, relocated: &[String]) -> Option<String> {
    invocation_read(map)
        .map(str::to_owned)
        .or_else(|| relocated_read(map, relocated))
}

/// A read of a path this body shows to be a copy of a protected file. Relocating
/// `.env` to another name used to be the way around the guard; now the copy makes
/// that other name protected too, for as long as the copy is in the history.
fn relocated_read(map: &Map<String, Value>, relocated: &[String]) -> Option<String> {
    if relocated.is_empty() || is_write_tool(map) {
        return None;
    }
    for text in invocation_strings(map) {
        let tokens = tokenize(text);
        for (index, token) in tokens.iter().enumerate() {
            if !is_read_position(&tokens, index) {
                continue;
            }
            if let Some(path) = relocated.iter().find(|path| path_names(token, path)) {
                return Some(path.clone());
            }
        }
    }
    None
}

/// Destinations that a protected file has demonstrably been copied to, collected
/// transitively: `cp .env /tmp/a` then `cp /tmp/a /tmp/b` protects both, because
/// every hop of the chain rides in the same request history.
///
/// `ponytail:` a destination given as a bare directory (`mv /tmp/a /tmp/dir`) is
/// tracked as that directory, not as `/tmp/dir/a`; the copy landing inside it is
/// missed. `ponytail:` also path matching, see [`path_names`].
fn relocated_paths(value: &Value) -> Vec<String> {
    let mut invocations = Vec::new();
    collect_invocations(value, &mut invocations);
    let mut paths: Vec<String> = Vec::new();
    loop {
        let before = paths.len();
        for map in &invocations {
            if is_write_tool(map) {
                continue;
            }
            for text in invocation_strings(map) {
                let tokens = tokenize(text);
                for (source, destination) in copy_pairs(&tokens) {
                    let source_is_secret = protected_segment(&tokens[source]).is_some()
                        || paths.iter().any(|path| path_names(&tokens[source], path));
                    if !source_is_secret {
                        continue;
                    }
                    let target = normalized_path(&tokens[destination]);
                    if !paths.contains(&target) {
                        paths.push(target);
                    }
                }
            }
        }
        if paths.len() == before {
            paths.sort();
            paths.dedup();
            return paths;
        }
    }
}

fn collect_invocations<'a>(value: &'a Value, out: &mut Vec<&'a Map<String, Value>>) {
    match value {
        Value::Object(map) => {
            if is_invocation(map) {
                out.push(map);
            }
            map.values()
                .for_each(|value| collect_invocations(value, out));
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_invocations(value, out)),
        _ => {}
    }
}

/// The keys that carry a tool's arguments across the provider schemas.
const ARGUMENT_KEYS: [&str; 7] = [
    "input",
    "arguments",
    "parameters",
    "command",
    "path",
    "file_path",
    "filename",
];

/// Every string a invocation carries as an argument: paths, shell commands, and
/// JSON smuggled inside a string.
fn invocation_strings(map: &Map<String, Value>) -> Vec<&str> {
    let mut out = Vec::new();
    for key in ARGUMENT_KEYS {
        if let Some(value) = map.get(key) {
            gather_strings(value, &mut out);
        }
    }
    out
}

fn gather_strings<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::Object(map) => map.values().for_each(|v| gather_strings(v, out)),
        Value::Array(values) => values.iter().for_each(|v| gather_strings(v, out)),
        Value::String(text) => out.push(text),
        _ => {}
    }
}

/// `(source, destination)` index pairs for every copy-like command in a token
/// stream, once the command has a source and somewhere to put it.
fn copy_pairs(tokens: &[String]) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    let mut start = 0;
    while start < tokens.len() {
        let end = tokens[start..]
            .iter()
            .position(|token| BOUNDARY.contains(&token.as_str()))
            .map_or(tokens.len(), |offset| start + offset);
        let segment = &tokens[start..end];
        let positionals: Vec<usize> = segment
            .iter()
            .enumerate()
            .filter(|(_, token)| !token.starts_with('-'))
            .skip(1)
            .map(|(offset, _)| start + offset)
            .collect();
        if positionals.len() > 1 && segment.first().is_some_and(|c| is_copy_command(c)) {
            let destination = *positionals.last().expect("checked non-empty");
            pairs.extend(
                positionals
                    .iter()
                    .take(positionals.len() - 1)
                    .map(|source| (*source, destination)),
            );
        }
        start = end + 1;
    }
    pairs
}

/// Whether a token names the given path: the same absolute path, the same path
/// under a different working directory, or — for a name too distinctive to be a
/// coincidence — the same basename.
fn path_names(token: &str, path: &str) -> bool {
    let candidate = normalized_path(token);
    let basename = path.rsplit('/').next().unwrap_or(path);
    candidate == path
        || candidate.ends_with(&format!("/{basename}"))
        || (basename.len() > 3 && candidate == basename)
}

/// A path token as it would appear on disk: quotes, escapes, and the glob
/// spellings [`protected_segment`] already normalizes away, removed.
fn normalized_path(token: &str) -> String {
    collapse_singleton_globs(&token.replace(['\'', '"'], ""))
        .replace(['*', '?'], "")
        .replace("\\", "/")
}

fn is_write_tool(map: &Map<String, Value>) -> bool {
    tool_name(map).is_some_and(|name| WRITE_TOOLS.contains(&name))
}

/// The call id a result answers to. Anthropic uses `id` on a `tool_use` block,
/// OpenAI chat completions on a `tool_calls` entry, and the Responses API
/// `call_id` on a `function_call` item.
fn invocation_id(map: &Map<String, Value>) -> Option<&str> {
    map.get("id")
        .and_then(Value::as_str)
        .or_else(|| map.get("call_id").and_then(Value::as_str))
}

fn blank_results(
    value: &mut Value,
    calls: &[ReadCall],
    blanked_ids: &mut Vec<String>,
    blanked: &mut Vec<String>,
) {
    match value {
        Value::Array(values) => {
            for value in values {
                blank_results(value, calls, blanked_ids, blanked);
            }
        }
        Value::Object(map) => {
            if let Some((id, label)) = answering_result(map, calls) {
                let mut payload = false;
                // Blank every key that could carry the file, so a body using both
                // spellings cannot leak through the one that was not expected.
                for key in ["content", "output"] {
                    if map.contains_key(key) {
                        map.insert(
                            key.to_owned(),
                            Value::String(format!(
                                "[gatekeeper withheld the contents of {label}. Do not retry the \
                                 read or reach for another tool: this proxy never forwards them \
                                 to the model provider. Ask the user for the value you need.]"
                            )),
                        );
                        payload = true;
                    }
                }
                // Paired either way: a result with no payload key carried nothing.
                blanked_ids.push(id);
                if payload {
                    blanked.push(label);
                }
                return;
            }
            for (_, value) in map.iter_mut() {
                blank_results(value, calls, blanked_ids, blanked);
            }
        }
        _ => {}
    }
}

/// The call id and label of the protected read this result answers, if it
/// answers one. Takes `calls` by shared reference so nothing borrowed out of the
/// body can outlive the check that reads it.
fn answering_result(map: &Map<String, Value>, calls: &[ReadCall]) -> Option<(String, String)> {
    let is_result = matches!(
        map.get("type"),
        Some(Value::String(kind)) if kind == "tool_result" || kind == "function_call_output"
    ) || matches!(
        map.get("role"),
        Some(Value::String(role)) if role == "tool"
    );
    if !is_result {
        return None;
    }
    let id = ["tool_use_id", "call_id", "tool_call_id"]
        .iter()
        .filter_map(|key| map.get(*key).and_then(Value::as_str))
        .next()?;
    calls
        .iter()
        .find(|call| call.id.as_deref() == Some(id))
        .map(|call| (id.to_owned(), call.label.clone()))
}

/// A tool-call *invocation* — a concrete call carrying arguments — as opposed to
/// a tool *definition** (`name` + `description` + schema, no arguments) or
/// ordinary message content.
fn is_invocation(map: &Map<String, Value>) -> bool {
    let typed = matches!(
        map.get("type"),
        Some(Value::String(kind)) if kind == "tool_use" || kind == "tool_call"
    );
    let named_call = map.contains_key("name")
        && ["input", "arguments", "parameters", "command"]
            .iter()
            .any(|key| map.contains_key(*key));
    // OpenAI: {"id": ..., "type": "function", "function": {"name", "arguments"}}
    let wrapped_function =
        matches!(map.get("function"), Some(Value::Object(inner)) if inner.contains_key("name"));
    typed || named_call || wrapped_function
}

fn invocation_read(map: &Map<String, Value>) -> Option<&'static str> {
    // Checked first so a write tool is exempt from the guard entirely.
    if is_write_tool(map) {
        return None;
    }
    for key in ARGUMENT_KEYS {
        match map.get(key) {
            Some(value @ (Value::Object(_) | Value::Array(_))) => {
                if let Some(hit) = args_read(value) {
                    return Some(hit);
                }
            }
            Some(Value::String(text)) => {
                if let Some(hit) = string_read(text) {
                    return Some(hit);
                }
            }
            _ => {}
        }
    }
    None
}

/// Every string leaf under a tool's arguments is treated as a path or command;
/// the guard knows no per-tool distinction beyond the write allowlist.
fn args_read(value: &Value) -> Option<&'static str> {
    match value {
        Value::Object(map) => map.values().find_map(args_read),
        Value::Array(values) => values.iter().find_map(args_read),
        Value::String(text) => string_read(text),
        _ => None,
    }
}

fn string_read(text: &str) -> Option<&'static str> {
    // OpenAI smuggles the argument object in a JSON *string*.
    let nested = serde_json::from_str::<Value>(text)
        .ok()
        .as_ref()
        .and_then(args_read);
    if nested.is_some() {
        return nested;
    }
    let tokens = tokenize(text);
    tokens.iter().enumerate().find_map(|(index, token)| {
        protected_segment(token).filter(|_| is_read_position(&tokens, index))
    })
}

/// Split on whitespace and shell connectors, emitting `;`, `|`, and `>` as
/// standalone tokens so command boundaries and redirections survive.
///
/// Shell connectors are spaced first so `x=n;` cannot glue the terminator onto
/// the assigned value.
fn tokenize(text: &str) -> Vec<String> {
    let spaced = text.replace([';', '|', '&'], " ; ").replace('>', " > ");
    let expanded = expand_assignments(&spaced);
    expanded
        .split_whitespace()
        .flat_map(|word| word.split(['(', ')', '{', '}']))
        .map(|token| token.trim_matches(|c| matches!(c, '"' | '\'' | '`' | '<' | ',' | ':' | '$')))
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Resolve the `name=value` pairs a command assigns to itself, so `x=n; cat
/// .e${x}v` is seen as the read of `.env` that it is.
///
/// `ponytail:` only covers assignments spelled out in the same argument. A value
/// inherited from the parent shell (`cat .e${x}v` with `x` set two commands ago)
/// is unknowable from the request, and blanket-failing every expansion to cover it
/// blocked ordinary work like `echo "built $(date)"` — so the guard now accepts
/// that gap, with PII redaction as the net. Upgrade path: a real shell parser.
fn expand_assignments(text: &str) -> Cow<'_, str> {
    let bindings: Vec<(&str, &str)> = text
        .split_whitespace()
        .filter_map(|token| token.split_once('='))
        .filter(|(name, value)| {
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !value.is_empty()
                && !value.contains('$')
        })
        .map(|(name, value)| (name, value.trim_matches(|c| matches!(c, '"' | '\'' | '`'))))
        .collect();
    if bindings.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut expanded = text.to_owned();
    for (name, value) in bindings {
        expanded = expanded
            .replace(&format!("${{{name}}}"), value)
            .replace(&format!("${name}"), value);
    }
    Cow::Owned(expanded)
}

/// The protected name a token names, if any. Compares the final path segment
/// exactly and case-sensitively, so `.env.example`, `.env.local`, `my.env`, and
/// `.envrc` never match.
fn collapse_singleton_globs(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if index + 2 < chars.len()
            && chars[index] == '['
            && chars[index + 2] == ']'
            && (chars[index + 1].is_ascii_alphanumeric() || chars[index + 1] == '.')
        {
            output.push(chars[index + 1]);
            index += 3;
        } else {
            output.push(chars[index]);
            index += 1;
        }
    }
    output
}

fn protected_segment(token: &str) -> Option<&'static str> {
    // Concatenated quotes and backslash escapes are equivalent to their plain
    // spelling in common shells: `.e''nv` and `.en\v` both name `.env`. Globs and
    // bracket expressions can name a protected file too; normalize the exact
    // bypass shapes found in the adversarial review, but do not expand arbitrary
    // shell syntax here.
    let normalized =
        collapse_singleton_globs(&token.replace(['\'', '"'], "")).replace(['*', '?'], "");
    let candidate = match normalized.rsplit_once(':') {
        // A `:line` suffix, as grep-style output and `file:line` arguments use.
        Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => normalized.as_str(),
    };
    // Utilities such as `dd` carry paths after an option assignment (`if=.env`),
    // and structured tools sometimes serialize them as `path=/srv/.env`.
    let candidate = candidate
        .rsplit_once('=')
        .map_or(candidate, |(_, path)| path);

    // A backslash is both a Windows separator and a shell escape. Check both
    // interpretations: `C:\\Users\\me\\.env` needs separators preserved, while
    // `.en\\v` names `.env` in a POSIX shell.
    for canonical in [candidate.replace('\\', "/"), candidate.replace('\\', "")] {
        if let Some((_, label)) = PROTECTED_PATH_SUFFIXES
            .iter()
            .find(|(suffix, _)| canonical.ends_with(suffix) || canonical == suffix[1..])
        {
            return Some(label);
        }
        let basename = canonical.rsplit('/').next().unwrap_or(&canonical);
        if let Some(name) = PROTECTED_BASENAMES
            .iter()
            .find(|name| **name == basename)
            .or_else(|| {
                // A file literally named `.key` is still a key file, so no stem
                // is required.
                PROTECTED_EXTENSIONS
                    .iter()
                    .find(|ext| basename.ends_with(**ext))
            })
        {
            return Some(name);
        }
    }
    None
}

/// Whether the token at `index` is being **read**, so its contents can turn up in
/// the tool result and ride the next request outbound.
///
/// Two shapes are not reads: a redirection target (`echo x > .env`), and any
/// operand of a copy or move (`cp .env.example .env`, `cp .env /tmp/x`) — such a
/// command moves bytes on the client's disk and prints nothing, so nothing of the
/// file leaves in the result. A relocation used to be refused as a read; that
/// bought nothing (the proxy sees the command only after it ran) and the
/// destination it created is protected directly now, see [`relocated_paths`].
fn is_read_position(tokens: &[String], index: usize) -> bool {
    if index > 0 && tokens[index - 1] == REDIRECT {
        return false;
    }
    let Some(command) = segment_command(tokens, index) else {
        return true;
    };
    if command == "dd" {
        // `dd if=.env` with no `of=` writes the file to stdout, so only the
        // destination side of a `dd` is a non-read.
        return !tokens[index].starts_with("of=");
    }
    if SINK_COMMANDS.contains(&command) {
        // `tee .env` sends everything on its stdin to each argument.
        return false;
    }
    if is_copy_command(command) {
        // Copying a protected file out and reading the copy is the bypass this
        // used to try to refuse; the destination is protected instead now, so
        // neither operand of a real copy needs to be a read.
        return copy_pairs(tokens).is_empty();
    }
    true
}

/// `cp`, `mv`, and friends: commands whose operands change what is on disk and
/// whose result carries no file contents.
fn is_copy_command(command: &str) -> bool {
    MOVE_COMMANDS.contains(&command) || COPY_COMMANDS.contains(&command)
}

/// The command whose argument list contains `index`, stopping at segment
/// boundaries so a later command cannot inherit an earlier one's operands.
fn segment_command(tokens: &[String], index: usize) -> Option<&str> {
    let start = tokens[..index]
        .iter()
        .rposition(|token| BOUNDARY.contains(&token.as_str()))
        .map_or(0, |position| position + 1);
    tokens.get(start).map(String::as_str)
}

/// The tool an invocation names, in either the flat or the OpenAI-wrapped shape.
fn tool_name(map: &Map<String, Value>) -> Option<&str> {
    map.get("name").and_then(Value::as_str).or_else(|| {
        map.get("function")
            .and_then(Value::as_object)
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn blocked(body: Value) -> bool {
        protected_file_read(&body).is_some()
    }

    fn invocation(name: &str, arguments: Value) -> Value {
        json!({"name": name, "input": arguments})
    }

    #[test]
    fn anthropic_read_of_dotenv_is_blocked() {
        assert!(blocked(
            json!({"messages": [{"role": "assistant", "content": [
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/app/.env"}}
            ]}]})
        ));
    }

    #[test]
    fn openai_tool_call_with_json_string_arguments_is_blocked() {
        assert!(blocked(json!({"tool_calls": [
            {"id": "1", "type": "function", "function": {
                "name": "read_file", "arguments": "{\"path\": \".env\"}"
            }}
        ]})));
    }

    #[test]
    fn bash_reads_are_blocked() {
        for command in [
            "cat .env",
            "head -n 20 /srv/app/.env",
            "grep -r TOKEN .env",
            "source .env && run",
            "sed -n 1p id.pem",
            "bat /home/deploy/id_rsa.pem",
            "cat /etc/ssl/private/server.key",
            "cat '.env'",
            "cat .env:12",
            "echo $(cat .env)",
            "awk '{print}' .env",
            "cp x ; cat .env",
            "cat secrets.pem | base64",
        ] {
            assert!(
                blocked(invocation("Bash", json!({"command": command}))),
                "expected block: {command}"
            );
        }
    }

    #[test]
    fn adversarial_shell_spellings_are_blocked() {
        for command in [
            "cat .e''nv",
            "cat .en\\v",
            "cat .env*",
            "cat .en?v",
            "cat [.]env",
            "cat .[e]nv",
            "cat .en[v]",
            "x=n; cat .e${x}v",
            "dd if=.env",
        ] {
            assert!(
                blocked(invocation("Bash", json!({"command": command}))),
                "expected block: {command}"
            );
        }
    }

    #[test]
    fn common_credential_files_are_blocked() {
        for path in [
            "id_rsa",
            "/home/me/.ssh/id_ecdsa",
            "/home/me/.ssh/id_ed25519",
            r"C:\Users\me\.ssh\id_rsa",
            r"C:\Users\me\.env",
            "~/.aws/credentials",
            "/home/me/.kube/config",
            ".npmrc",
            ".git-credentials",
            ".pgpass",
            "secrets.yaml",
            "secrets.yml",
        ] {
            assert!(
                blocked(invocation("Read", json!({"file_path": path}))),
                "expected block: {path}"
            );
        }
    }

    #[test]
    fn the_reported_name_is_the_protected_basename() {
        assert_eq!(
            protected_file_read(&invocation("Read", json!({"file_path": "secrets.pem"}))),
            Some(".pem")
        );
        assert_eq!(
            protected_file_read(&invocation(
                "Grep",
                json!({"pattern": "BEGIN", "path": "id.key"})
            )),
            Some(".key")
        );
        assert_eq!(
            protected_file_read(&invocation("Read", json!({"file_path": ".env"}))),
            Some(".env")
        );
    }

    /// The regression the fail-closed expansion rule caused: ordinary shell that
    /// mentions no protected file must reach the provider.
    #[test]
    fn benign_shell_expansion_is_allowed() {
        for command in [
            r#"echo "built $(date)""#,
            "cd ${PROJECT_DIR}/src && ls",
            "git log --oneline -5 | head",
            "rm -rf ./target",
            "cat ${README}",
            "test -f $HOME/.config/settings.json && echo present",
        ] {
            assert!(
                !blocked(invocation("Bash", json!({"command": command}))),
                "expected allow: {command}"
            );
        }
    }

    #[test]
    fn shell_writes_are_allowed() {
        for command in [
            "cp .env.example .env",
            "echo SECRET=x > .env",
            "echo SECRET=x >> .env",
            "tee .env < input",
            "truncate -s 0 .env",
            "printf 'A=1\\n' > app/.env",
            "dd if=/dev/zero of=.env count=0",
        ] {
            assert!(
                !blocked(invocation("Bash", json!({"command": command}))),
                "expected allow: {command}"
            );
        }
    }

    /// Relocating a protected file is allowed as a tool call — the proxy only sees
    /// the command after it already ran, so refusing bought nothing — but the
    /// destination inherits the protection: reading the copy is withheld, and a
    /// copy of a copy stays protected down the chain.
    #[test]
    fn a_copy_of_a_protected_file_is_protected_wherever_it_lands() {
        let mut body = json!({"messages": [
            {"role": "assistant", "content": [
                read_use("toolu_cp", "Bash", json!({"command": "cp .env /tmp/local.env"}))
            ]},
            {"role": "user", "content": [read_result("toolu_cp", "copied 1 file")]},
            {"role": "assistant", "content": [
                read_use("toolu_mv", "Bash", json!({"command": "mv /tmp/local.env /tmp/keep.env"}))
            ]},
            {"role": "user", "content": [read_result("toolu_mv", "")]},
            {"role": "assistant", "content": [
                read_use("toolu_cat", "Bash", json!({"command": "cat /tmp/keep.env"}))
            ]},
            {"role": "user", "content": [read_result("toolu_cat", "SECRET=ZEBRAqzx3")]},
            {"role": "assistant", "content": [
                read_use("toolu_other", "Bash", json!({"command": "cat /tmp/unrelated.txt"}))
            ]},
            {"role": "user", "content": [read_result("toolu_other", "hello ANTLERqzx3")]},
        ]});

        let withheld = withhold_protected_reads(&mut body);
        let text = body.to_string();

        assert_eq!(
            withheld.blanked,
            ["/tmp/keep.env".to_owned()],
            "only the read of the relocated file is withheld"
        );
        // The copy itself rides along untouched: its result carries no contents.
        assert!(text.contains("copied 1 file"), "{text}");
        assert!(!text.contains("ZEBRAqzx3"), "{text}");
        assert!(text.contains("ANTLERqzx3"), "{text}");
    }

    #[test]
    fn a_copy_command_is_not_a_read() {
        for command in [
            "mv template.key .key",
            "install -m 600 example.pem .pem",
            "mv .env /tmp/x",
            "cp secrets.pem /tmp",
            "cp .env /tmp/stolen",
        ] {
            assert!(
                !blocked(invocation("Bash", json!({"command": command}))),
                "expected allow: {command}"
            );
        }
    }

    #[test]
    fn structured_write_tools_are_allowed() {
        for name in WRITE_TOOLS {
            assert!(
                !blocked(invocation(name, json!({"file_path": "/app/.env"}))),
                "{name} should be exempt"
            );
        }
    }

    #[test]
    fn near_miss_names_are_allowed() {
        for path in [
            ".env.example",
            ".env.local",
            ".env.production",
            ".envrc",
            "my.env",
            "ENV",
            "id.pub",
            "key.pem.example",
            ".keys",
            "pem",
            "keys.json",
        ] {
            assert!(
                !blocked(invocation("Read", json!({"file_path": path}))),
                "expected allow: {path}"
            );
        }
    }

    #[test]
    fn prose_and_tool_definitions_are_not_blocked() {
        assert!(!blocked(json!({"messages": [
            {"role": "user", "content": "Please open my .env file and check id_rsa.pem"}
        ]})));
        assert!(!blocked(json!({"tools": [
            {"name": "read_file", "description": "Reads .env files",
             "input_schema": {"properties": {"path": {"type": "string"}}}}
        ]})));
    }

    #[test]
    fn public_keys_are_not_read() {
        assert!(!blocked(
            json!({"name": "Bash", "input": {"command": "cat id_rsa.pub"}})
        ));
    }

    #[test]
    fn bare_scalars_cannot_carry_an_invocation() {
        assert!(!blocked(json!("cat .env")));
        assert!(!blocked(json!({"a": 1, "b": true, "c": null})));
    }

    fn read_use(id: &str, name: &str, arguments: Value) -> Value {
        json!({"type": "tool_use", "id": id, "name": name, "input": arguments})
    }

    fn read_result(id: &str, payload: &str) -> Value {
        json!({"type": "tool_result", "tool_use_id": id, "content": payload})
    }

    /// The payload goes, the request does not: the provider never sees the file,
    /// and the agent gets a reason instead of an HTTP failure to retry around.
    #[test]
    fn an_anthropic_read_result_is_blanked() {
        let mut body = json!({"messages": [
            {"role": "assistant", "content": [read_use("toolu_1", "Read", json!({"file_path": "/app/.env"}))]},
            {"role": "user", "content": [read_result("toolu_1", "UPSTREAM_API_KEY=ZEBRAqzx3")]},
        ]});

        let withheld = withhold_protected_reads(&mut body);

        assert_eq!(withheld.blanked, [".env".to_owned()]);
        assert!(withheld.unpaired.is_empty());
        let text = body.to_string();
        assert!(!text.contains("ZEBRAqzx3"), "{text}");
        assert!(text.contains("withheld the contents of .env"), "{text}");
        // The invocation itself stays, so the conversation history is intact.
        assert!(text.contains("/app/.env"), "{text}");
    }

    #[test]
    fn openai_and_responses_api_results_are_blanked() {
        let mut chat = json!({"messages": [
            {"role": "assistant", "tool_calls": [
                {"id": "call_1", "type": "function", "function": {
                    "name": "read_file", "arguments": "{\"path\": \"server.key\"}"}}
            ]},
            {"role": "tool", "tool_call_id": "call_1", "content": "BEGIN PRIVATE ZEBRAqzx3"}
        ]});
        assert_eq!(
            withhold_protected_reads(&mut chat).blanked,
            [".key".to_owned()],
            "chat completions shape"
        );
        assert!(!chat.to_string().contains("ZEBRAqzx3"));

        let mut responses = json!({"input": [
            {"type": "function_call", "call_id": "cx_1", "name": "shell",
             "arguments": "{\"command\": \"cat ~/.aws/credentials\"}"},
            {"type": "function_call_output", "call_id": "cx_1", "output": "aws_secret ZEBRAqzx3"}
        ]});
        assert_eq!(
            withhold_protected_reads(&mut responses).blanked,
            ["AWS credentials".to_owned()],
            "responses shape"
        );
        assert!(!responses.to_string().contains("ZEBRAqzx3"));
    }

    /// Only the paired result is blanked: an unrelated read of `.env.example`
    /// keeps its contents, and so does a result answering some other call id.
    #[test]
    fn only_the_paired_result_is_blanked() {
        let mut body = json!({"messages": [{"role": "user", "content": [
            read_result("toolu_1", "SECRET=ZEBRAqzx3"),
            read_result("toolu_2", "EXAMPLE=ANTLERqzx3"),
        ]}], "tool_uses": [
            read_use("toolu_other", "Read", json!({"file_path": "/app/.env"})),
            read_use("toolu_2", "Read", json!({"file_path": "/app/.env.example"})),
        ]});

        let withheld = withhold_protected_reads(&mut body);

        assert!(withheld.blanked.is_empty());
        assert_eq!(withheld.unpaired, [".env".to_owned()]);
        let text = body.to_string();
        assert!(text.contains("SECRET=ZEBRAqzx3"), "{text}");
        assert!(text.contains("EXAMPLE=ANTLERqzx3"), "{text}");
    }

    /// Real clients send `content` as a block array, not a string, and split a
    /// file across several text blocks. The whole payload goes either way.
    #[test]
    fn a_block_array_result_is_blanked() {
        let mut body = json!({"messages": [
            read_use("toolu_1", "Read", json!({"file_path": "/srv/.env"})),
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": [
                {"type": "text", "text": "LINE_ONE=ZEBRAqzx3"},
                {"type": "text", "text": "LINE_TWO=ANTLERqzx3"}
            ]}
        ]});

        assert_eq!(
            withhold_protected_reads(&mut body).blanked,
            [".env".to_owned()]
        );
        assert!(!body.to_string().contains("ZEBRAqzx3"), "{body}");
        assert!(!body.to_string().contains("ANTLERqzx3"), "{body}");
    }

    /// A write's result is nobody's secret: `cp .env.example .env` must survive
    /// untouched so setup flows keep working.
    #[test]
    fn write_results_and_prose_survive() {
        let mut body = json!({"messages": [
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_w", "name": "Bash",
                 "input": {"command": "cp .env.example .env"}}
            ]},
            {"role": "user", "content": [read_result("toolu_w", "copied 1 file")]},
            {"role": "user", "content": "the .env held BEGIN PRIVATE ZEBRAqzx3"}
        ]});

        let withheld = withhold_protected_reads(&mut body);

        assert!(withheld.blanked.is_empty() && withheld.unpaired.is_empty());
        assert!(body.to_string().contains("ZEBRAqzx3"));
    }

    /// `is_error` results are blanked too: a failed read still echoes back paths
    /// and sometimes a line of the file, and a guard cannot tell which.
    #[test]
    fn an_error_result_is_blanked_as_well() {
        let mut body = json!({"messages": [
            read_use("toolu_1", "Read", json!({"file_path": "id_rsa"})),
            {"type": "tool_result", "tool_use_id": "toolu_1", "is_error": true,
             "content": "failed to parse id_rsa: BEGIN ZEBRAqzx3"}
        ]});

        assert_eq!(
            withhold_protected_reads(&mut body).blanked,
            ["id_rsa".to_owned()]
        );
        assert!(!body.to_string().contains("ZEBRAqzx3"));
    }
}

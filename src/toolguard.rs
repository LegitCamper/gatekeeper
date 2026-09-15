//! Tool-call guard: denies outbound requests whose tool-call invocations try to
//! **read** files holding private key material or environment secrets.
//!
//! The guard looks only at invocation shapes (Anthropic `tool_use` blocks,
//! OpenAI `tool_calls`/`function.arguments`, and anything carrying a `command`
//! argument such as Bash), never at prose, tool *definitions*, or response
//! bodies. Writes are allowed — an agent initializing `.env` from
//! `.env.example` is the intended setup flow — reads are not, because a read's
//! contents ride the next outbound request to the provider untouched.
//!
//! `ponytail:` shell rules are conservative token heuristics, not a shell parser.
//! Known quote, escape, glob, assignment, connector, and redirection forms are
//! normalized; arbitrary shell expansion cannot be proven safe. Upgrade path is a
//! real command parser or blocking all shell calls that mention protected stems.

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
    let name = map.get("name").and_then(Value::as_str).or_else(|| {
        map.get("function")
            .and_then(Value::as_object)
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
    });
    if name.is_some_and(|name| WRITE_TOOLS.contains(&name)) {
        return None;
    }
    let shell = name
        .is_some_and(|name| matches!(name.to_ascii_lowercase().as_str(), "bash" | "shell" | "sh"));
    if shell && map.values().any(contains_dynamic_shell) {
        // A token heuristic cannot know what `${x}`, `$()`, or backticks expand
        // to. Fail closed for shell invocations rather than claiming exotic
        // spellings are safe.
        return Some("dynamic shell expansion");
    }
    for key in [
        "input",
        "arguments",
        "parameters",
        "command",
        "path",
        "file_path",
        "filename",
    ] {
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

fn contains_dynamic_shell(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.values().any(contains_dynamic_shell),
        Value::Array(values) => values.iter().any(contains_dynamic_shell),
        Value::String(text) => text.contains("${") || text.contains("$(") || text.contains('`'),
        _ => false,
    }
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
        let name = protected_segment(token)?;
        (!is_write_position(&tokens, index, name)).then_some(name)
    })
}

/// Split on whitespace and shell connectors, emitting `;`, `|`, and `>` as
/// standalone tokens so command boundaries and redirections survive.
fn tokenize(text: &str) -> Vec<String> {
    text.replace([';', '|', '&'], " ; ")
        .replace('>', " > ")
        .split_whitespace()
        .flat_map(|word| word.split(['(', ')', '{', '}']))
        .map(|token| token.trim_matches(|c| matches!(c, '"' | '\'' | '`' | '<' | ',' | ':' | '$')))
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
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

/// `echo x > .env` and `cp .env.example .env` are writes; any other position of
/// a protected name is a read.
fn is_write_position(tokens: &[String], index: usize, name: &str) -> bool {
    if index > 0 && tokens[index - 1] == REDIRECT {
        return true;
    }
    write_destination(tokens, index).is_some_and(|destination| destination == name)
}

/// The protected name this token is writing to, when the enclosing command
/// treats its position as a destination.
fn write_destination(tokens: &[String], index: usize) -> Option<&'static str> {
    let start = tokens[..index]
        .iter()
        .rposition(|token| BOUNDARY.contains(&token.as_str()))
        .map_or(0, |position| position + 1);
    let command = tokens.get(start)?;
    let sink = SINK_COMMANDS.iter().any(|c| c == command);
    let copy_like = sink
        || MOVE_COMMANDS.iter().any(|c| c == command)
        || COPY_COMMANDS.iter().any(|c| c == command);
    if !copy_like {
        return None;
    }
    let positionals: Vec<usize> = (start..tokens.len())
        .filter(|&i| !tokens[i].starts_with('-'))
        .collect();
    let destination = if sink {
        // `tee .env` writes every argument it is given.
        positionals.contains(&index) && positionals.len() > 1
    } else {
        // The destination is the last argument, and a source must also exist.
        positionals.last() == Some(&index) && positionals.len() > 2
    };
    destination
        .then(|| protected_segment(&tokens[index]))
        .flatten()
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
            "cp .env /tmp/stolen",
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

    #[test]
    fn shell_writes_are_allowed() {
        for command in [
            "cp .env.example .env",
            "echo SECRET=x > .env",
            "echo SECRET=x >> .env",
            "tee .env < input",
            "truncate -s 0 .env",
            "printf 'A=1\\n' > app/.env",
        ] {
            assert!(
                !blocked(invocation("Bash", json!({"command": command}))),
                "expected allow: {command}"
            );
        }
    }

    /// A copy/move that *reads* a protected file is blocked even though the
    /// command writes: relocating a secret to an unprotected name is exactly
    /// how a guard would otherwise be stepped around.
    #[test]
    fn relocating_a_protected_file_is_blocked() {
        for command in [
            "mv template.key .key",
            "install -m 600 example.pem .pem",
            "mv .env /tmp/x",
            "cp secrets.pem /tmp",
        ] {
            assert!(
                blocked(invocation("Bash", json!({"command": command}))),
                "expected block: {command}"
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
}

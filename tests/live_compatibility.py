#!/usr/bin/env python3
"""Opt-in direct/proxy checks. Standard library only; all services and models supplied by caller."""

import argparse
import base64
import json
import os
from pathlib import Path
import random
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

EMAIL = "fixture.contact@example.com"
SCHEMA = {"type": "object", "properties": {"email": {"type": "string"}},
          "required": ["email"], "additionalProperties": False}
TOOL = {"name": "lookup_contact", "description": "Look up contact and return screenshot.",
        "parameters": SCHEMA}
PATHS = {"responses": "/v1/responses", "chat": "/v1/chat/completions", "ollama": "/api/chat"}


def check(condition, reason):
    if not condition:
        raise ValueError(reason)


def image_fixture():
    def chunk(kind, data):
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))

    head = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", 32, 32, 8, 2, 0, 0, 0))
    metadata = b"fixture\0"
    metadata += b"x" * (-(len(head) + 8 + len(metadata)) % 3)
    metadata += base64.b64decode("AAAA/4155552671/AAAAAAAA")
    pixels = random.Random(42).randbytes(32 * 32 * 3)
    rows = b"".join(b"\0" + pixels[i:i + 96] for i in range(0, len(pixels), 96))
    png = head + chunk(b"tEXt", metadata) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")
    return "data:image/png;base64," + base64.b64encode(png).decode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def decode(raw, content_type, protocol, stream):
    """Normalize provider streams; retain compatibility defects as explicit issues."""
    issues = []
    if not stream:
        value = json.loads(raw)
        check(not value.get("error"), "provider returned an error body")
        return value, issues
    if protocol == "ollama":
        events = [json.loads(line) for line in raw.splitlines() if line.strip()]
        check(events and events[-1].get("done") is True, "missing Ollama done event")
        check(not any(event.get("error") for event in events), "Ollama stream error")
        message = {"role": "assistant", "content": ""}
        calls = []
        for event in events:
            part = event.get("message", {})
            message["content"] += part.get("content", "")
            calls.extend(part.get("tool_calls", []))
        if calls:
            message["tool_calls"] = calls
        return {"message": message}, issues
    check("text/event-stream" in content_type, "stream request did not return SSE")
    events, data, done = [], [], False
    for line in raw.replace("\r\n", "\n").split("\n") + [""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and data:
            payload, data = "\n".join(data), []
            if payload == "[DONE]":
                done = True
            else:
                events.append(json.loads(payload))
    check(events, "empty SSE stream")
    check(not any(e.get("error") or e.get("type") in ("error", "response.failed", "response.incomplete")
                  for e in events), "provider stream failed")
    if protocol == "responses":
        completed = [e["response"] for e in events if e.get("type") == "response.completed"]
        check(completed, "missing response.completed")
        value = completed[-1]
        items = [e["item"] for e in events if e.get("type") == "response.output_item.done"]
        if not value.get("output") and items:
            issues.append("response.completed has empty output; reconstructed from item events")
            value["output"] = items
        return value, issues
    if not done:
        issues.append("missing [DONE] sentinel")
    check(any(c.get("finish_reason") for e in events for c in e.get("choices", [])),
          "missing Chat finish_reason")
    message, calls = {"role": "assistant", "content": ""}, {}
    for event in events:
        for choice in event.get("choices", []):
            delta = choice.get("delta", {})
            message["content"] += delta.get("content") or ""
            for piece in delta.get("tool_calls", []):
                call = calls.setdefault(piece["index"], {"id": "", "type": "function",
                                                       "function": {"name": "", "arguments": ""}})
                call["id"] = piece.get("id") or call["id"]
                for key in ("name", "arguments"):
                    call["function"][key] += piece.get("function", {}).get(key, "")
    if calls:
        message["tool_calls"] = [calls[i] for i in sorted(calls)]
    return {"choices": [{"message": message}]}, issues


def http(base, path, body, args, protocol=None, stream=False):
    headers = {"Content-Type": "application/json"}
    if args.key:
        headers[args.auth_header] = args.auth_value
    request = urllib.request.Request(base.rstrip("/") + path,
                                     data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=args.timeout) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            check(len(raw) <= 4 * 1024 * 1024, "test response exceeds 4 MiB")
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as error:
        # Never print upstream bodies or credentials in test reports.
        raise ValueError(f"HTTP {error.code} at {path}") from None
    return decode(raw.decode(), content_type, protocol, stream)


def output_text(value, protocol):
    if protocol == "responses":
        check(isinstance(value.get("output"), list), "Responses JSON missing output array")
        return "".join(part["text"] for item in value["output"] if item["type"] == "message"
                       for part in item["content"] if part["type"] == "output_text")
    return (value["message"] if protocol == "ollama" else value["choices"][0]["message"])["content"]


def unfence(text):
    # Models answer schema prompts with a ```json fence often enough that a bare
    # json.loads would read provider formatting as a proxy failure.
    body = text.strip()
    if body.startswith("```"):
        body = body.split("\n", 1)[-1].rsplit("```", 1)[0]
    return body


def run_case(base, model, protocol, stream, test, args):
    issues = []

    def send(body, path=None):
        value, found = http(base, path or PATHS[protocol], body, args, protocol, body.get("stream", False) if body else False)
        issues.extend(found)
        return value

    if test == "metadata":
        paths = ["/api/tags", "/api/ps", "/api/version"] if protocol == "ollama" else ["/v1/models"]
        for path in paths:
            value = send(None, path)
            check(isinstance(value, dict), "discovery response must be an object")
        return issues
    if test == "embeddings":
        path = "/api/embed" if protocol == "ollama" else "/v1/embeddings"
        value = send({"model": model, "input": EMAIL}, path)
        vectors = value.get("embeddings") if protocol == "ollama" else [v["embedding"] for v in value.get("data", [])]
        check(vectors and all(isinstance(v, list) and v and all(isinstance(n, (int, float)) for n in v) for v in vectors),
              "missing numeric embedding vectors")
        return issues
    prompt = f"Return only a JSON object with email equal to {EMAIL}."
    if test == "structured":
        body = {"model": model, "stream": stream}
        if protocol == "responses":
            body.update(input=prompt, text={"format": {"type": "json_schema", "name": "contact_record", "strict": True, "schema": SCHEMA}})
        else:
            body["messages"] = [{"role": "user", "content": prompt}]
            if protocol == "ollama":
                body["format"] = SCHEMA
            else:
                body["response_format"] = {"type": "json_schema", "json_schema": {"name": "contact_record", "strict": True, "schema": SCHEMA}}
        check(json.loads(unfence(output_text(send(body), protocol))) == {"email": EMAIL},
              "structured output failed round trip")
        return issues
    if test == "compact":
        check(protocol == "responses", "compact check requires Responses protocol")
        value = send({"model": model, "input": [{"role": "user", "content": prompt}]}, "/v1/responses/compact")
        check(isinstance(value.get("output"), list), "compaction missing output")
        response = send({"model": model, "input": value["output"] + [{"role": "user", "content": "Reply OK."}], "stream": False})
        check(output_text(response, protocol), "compaction replay produced no text")
        return issues

    image = image_fixture() if test == "image" else None
    prompt = f"Call lookup_contact with email {EMAIL}. After result, reply READY followed by returned email."
    first = {"model": model, "stream": stream}
    if protocol == "responses":
        first.update(input=[{"role": "user", "content": prompt}], tools=[{"type": "function", **TOOL}],
                     tool_choice="required", include=["reasoning.encrypted_content"])
        response = send(first)
        check(isinstance(response.get("output"), list), "Responses JSON missing output array")
        calls = [v for v in response["output"] if v["type"] == "function_call"]
        check(len(calls) == 1 and calls[0]["name"] == TOOL["name"], "expected one lookup_contact call")
        check(json.loads(calls[0]["arguments"]) == {"email": EMAIL}, "tool arguments failed round trip")
        result = [{"type": "input_text", "text": "READY " + EMAIL}]
        if image:
            result.append({"type": "input_image", "image_url": image})
        second = {**first, "tool_choice": "none", "input": first["input"] + response["output"] + [
            {"type": "function_call_output", "call_id": calls[0]["call_id"], "output": result if image else "READY " + EMAIL}]}
    else:
        first.update(messages=[{"role": "user", "content": prompt}], tools=[{"type": "function", "function": TOOL}])
        if protocol == "chat":
            first["tool_choice"] = {"type": "function", "function": {"name": TOOL["name"]}}
        response = send(first)
        assistant = response["message"] if protocol == "ollama" else response["choices"][0]["message"]
        calls = assistant.get("tool_calls", [])
        check(len(calls) == 1 and calls[0]["function"]["name"] == TOOL["name"], "expected one lookup_contact call")
        arguments = calls[0]["function"]["arguments"]
        check((json.loads(arguments) if isinstance(arguments, str) else arguments) == {"email": EMAIL}, "tool arguments failed round trip")
        result = {"role": "tool", "content": "READY " + EMAIL}
        result.update({"tool_name": TOOL["name"]} if protocol == "ollama" else {"tool_call_id": calls[0]["id"]})
        messages = first["messages"] + [assistant, result]
        if image:
            messages.append({"role": "user", "content": "Inspect image and repeat READY and returned email.", "images": [image.split(",", 1)[1]]}
                            if protocol == "ollama" else {"role": "user", "content": [{"type": "text", "text": "Inspect image and repeat READY and returned email."}, {"type": "image_url", "image_url": {"url": image}}]})
        second = {**first, "messages": messages}
        if protocol == "chat":
            second["tool_choice"] = "none"
        else:
            second.pop("tools", None)
    text = output_text(send(second), protocol)
    check("READY" in text and EMAIL in text, "tool result failed round trip")
    return issues


def self_test():
    image = image_fixture()
    check("/4155552671/" in image, "image fixture must trigger old phone redaction")
    check(base64.b64decode(image.split(",", 1)[1]).startswith(b"\x89PNG"), "valid PNG signature")
    lines = [json.dumps({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_fixture", "function": {"name": "lookup_contact", "arguments": '{"email":"'}}]}, "finish_reason": None}]}),
             json.dumps({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": EMAIL + '"}'}}]}, "finish_reason": "tool_calls"}]})]
    raw = "".join("data: " + line + "\r\n\r\n" for line in lines)
    result, issues = decode(raw, "text/event-stream", "chat", True)
    check(issues == ["missing [DONE] sentinel"], "stream defect must be reported")
    check(json.loads(result["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]) == {"email": EMAIL}, "split arguments")
    check(not decode(raw + "data: [DONE]\n\n", "text/event-stream", "chat", True)[1], "complete stream")
    result, issues = decode('data: {"type":"response.output_item.done","item":{"type":"message"}}\n\ndata: {"type":"response.completed","response":{"output":[]}}\n\n', "text/event-stream", "responses", True)
    check(issues and result["output"] == [{"type": "message"}], "empty terminal output must be reported")
    result, _ = decode('{"message":{"content":"OK"},"done":false}\n{"message":{"content":""},"done":true}\n', "application/x-ndjson", "ollama", True)
    check(result["message"]["content"] == "OK", "NDJSON decoding")
    try:
        decode('data: {"type":"response.failed"}\n\n', "text/event-stream", "responses", True)
    except ValueError:
        pass
    else:
        raise ValueError("stream error incorrectly passed")
    print("live runner self-check passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-url", default=os.getenv("GATEKEEPER_TEST_UPSTREAM"))
    parser.add_argument("--proxy-url", default=os.getenv("GATEKEEPER_TEST_PROXY"), help="otherwise spawn local Gatekeeper")
    parser.add_argument("--binary", default="target/debug/gatekeeper")
    parser.add_argument("--model", action="append", default=[], help="repeat for each model; no built-in model IDs")
    parser.add_argument("--protocol", action="append", choices=list(PATHS), default=[])
    parser.add_argument("--checks", default="tool,image,structured", help="comma-separated: tool,image,structured,compact,embeddings,metadata")
    parser.add_argument("--auth-header", default=os.getenv("GATEKEEPER_TEST_AUTH_HEADER", "authorization"))
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    args.key = os.getenv("GATEKEEPER_TEST_API_KEY", "")
    args.auth_value = ("Bearer " if args.auth_header.lower() == "authorization" else "") + args.key
    args.model = args.model or os.getenv("GATEKEEPER_TEST_MODELS", "").split(",")
    args.protocol = args.protocol or ["responses"]
    tests = args.checks.split(",")
    if not args.upstream_url or not all(args.model):
        parser.error("upstream URL and at least one model are required")
    if args.timeout <= 0 or not set(tests) <= {"tool", "image", "structured", "compact", "embeddings", "metadata"}:
        parser.error("invalid timeout or checks")
    for url in filter(None, [args.upstream_url, args.proxy_url]):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            parser.error("URLs must be HTTP(S) base URLs without credentials, query, or fragment")
    process = None
    failed = 0
    try:
        if not args.proxy_url:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            args.proxy_url = f"http://127.0.0.1:{port}"
            env = {k: v for k, v in os.environ.items() if k not in ("UPSTREAM_API_KEY", "ANTHROPIC_API_KEY")}
            env.update(TARGET_URL=args.upstream_url, LISTEN_ADDR=f"127.0.0.1:{port}",
                       UPSTREAM_AUTH_HEADER=args.auth_header, GATEKEEPER_REDACT="", GATEKEEPER_REDACT_IDENTITY="", RUST_LOG="error")
            if args.key:
                env["UPSTREAM_API_KEY"] = args.auth_value
            process = subprocess.Popen([str(Path(args.binary).resolve())], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 10
            while True:
                try:
                    with urllib.request.urlopen(args.proxy_url + "/health", timeout=1):
                        break
                except (OSError, urllib.error.URLError):
                    check(process.poll() is None and time.monotonic() < deadline, "local Gatekeeper did not start")
                    time.sleep(0.05)
        for model in args.model:
            for protocol in args.protocol:
                for test in tests:
                    for stream in ([False, True] if test in ("tool", "image", "structured") else [False]):
                        outcomes = []
                        for base in [args.upstream_url, args.proxy_url]:
                            try:
                                outcomes.append({"issues": run_case(base, model, protocol, stream, test, args)})
                            except (ValueError, KeyError, IndexError, TypeError, OSError, urllib.error.URLError) as error:
                                detail = str(error)
                                if args.key:
                                    detail = detail.replace(args.key, "<redacted>")
                                outcomes.append({"error": detail[:300]})
                        direct, proxied = outcomes
                        status = ("UPSTREAM_FAILURE" if "error" in direct else "PROXY_FAILURE" if "error" in proxied
                                  or set(proxied["issues"]) - set(direct["issues"]) else "UPSTREAM_QUIRK" if direct["issues"] else "PASS")
                        failed += status != "PASS"
                        print(json.dumps({"model": model, "protocol": protocol, "check": test, "stream": stream,
                                          "status": status, "direct": direct, "proxy": proxied}), flush=True)
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return int(failed > 0)


if __name__ == "__main__":
    sys.exit(main())

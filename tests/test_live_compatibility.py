"""Exercise the opt-in runner against a local protocol fixture, never a provider account."""

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
import unittest

import live_compatibility as live


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body, content_type="application/json"):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply({"data": [], "models": [], "version": "fixture"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        encoded = json.dumps(body)
        for image in re.findall(r"data:image/png;base64,([A-Za-z0-9+/=\[\]_-]+)", encoded):
            if not base64.b64decode(image, validate=True).startswith(b"\x89PNG"):
                self.send_error(400)
                return
        found = re.search(r"fixture\.contact@example\.com|\[(?:EMAIL|TOKEN)_[0-9a-f]{12}\]", encoded)
        contact = found.group() if found else live.EMAIL
        if self.path.endswith(("/embeddings", "/embed")):
            self.reply({"data": [{"embedding": [0.25, -0.5]}], "embeddings": [[0.25, -0.5]]})
            return
        if self.path.endswith("/compact"):
            self.reply({"output": body["input"]})
            return
        structured = "response_format" in body or "format" in body or "text" in body
        text = json.dumps({"email": contact}) if structured else "READY " + contact
        tool = bool(body.get("tools")) and "function_call_output" not in encoded and not any(
            message.get("role") == "tool" for message in body.get("messages", []))
        arguments = json.dumps({"email": contact})
        if self.path.endswith("/responses"):
            item = {"type": "function_call", "id": "fc_fixture", "call_id": "call_fixture",
                    "name": "lookup_contact", "arguments": arguments} if tool else {
                        "type": "message", "id": "msg_fixture", "role": "assistant",
                        "content": [{"type": "output_text", "text": text}]}
            response = {"status": "completed", "output": [item], "error": None}
            if body.get("stream"):
                events = [{"type": "response.output_item.done", "item": item},
                          {"type": "response.completed", "response": response}]
                self.reply("".join("data: " + json.dumps(event) + "\n\n" for event in events), "text/event-stream")
            else:
                self.reply(response)
        elif self.path.endswith("/api/chat"):
            message = {"role": "assistant", "content": "" if tool else text}
            if tool:
                message["tool_calls"] = [{"function": {"name": "lookup_contact", "arguments": {"email": contact}}}]
            if body.get("stream"):
                self.reply(json.dumps({"message": message, "done": False}) + "\n" +
                           json.dumps({"message": {"content": ""}, "done": True}) + "\n", "application/x-ndjson")
            else:
                self.reply({"message": message, "done": True})
        else:
            message = {"role": "assistant", "content": "" if tool else text}
            if tool:
                message["tool_calls"] = [{"id": "call_fixture", "type": "function",
                                          "function": {"name": "lookup_contact", "arguments": arguments}}]
            if not body.get("stream"):
                self.reply({"choices": [{"message": message}]})
                return
            if tool:
                deltas = [{"tool_calls": [{"index": 0, "id": "call_fixture", "type": "function",
                                           "function": {"name": "lookup_contact", "arguments": ""}}]}]
                deltas.extend({"tool_calls": [{"index": 0, "function": {"arguments": char}}]} for char in arguments)
            else:
                deltas = [{"content": char} for char in text]
            events = [{"choices": [{"index": 0, "delta": delta, "finish_reason": None}]} for delta in deltas]
            events.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls" if tool else "stop"}]})
            self.reply("".join("data: " + json.dumps(event) + "\n\n" for event in events) + "data: [DONE]\n\n", "text/event-stream")


class LiveRunnerTests(unittest.TestCase):
    def test_parser_rejects_errors_and_reports_incomplete_streams(self):
        live.self_test()

    def test_configurable_direct_and_proxy_matrix(self):
        root = Path(__file__).resolve().parents[1]
        binary = root / "target/debug/gatekeeper"
        self.assertTrue(binary.exists(), "run cargo build --locked before this test")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            command = [sys.executable, str(root / "tests/live_compatibility.py"), "--binary", str(binary),
                       "--upstream-url", f"http://127.0.0.1:{server.server_port}", "--model", "fixture-model"]
            result = subprocess.run(command + ["--protocol", "responses", "--protocol", "chat", "--protocol", "ollama",
                                               "--checks", "tool,image,structured,embeddings,metadata"],
                                    capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(rows), 24)
            self.assertTrue(all(row["status"] == "PASS" for row in rows))
            result = subprocess.run(command + ["--checks", "compact"], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()

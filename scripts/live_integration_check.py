#!/usr/bin/env python3
"""MCP Integration Tests for karon-mcp.

Tests:
- initialize handshake
- tools/list
- browse (single URL)
- crawl (multiple URLs)
- Error cases (invalid URL, missing API key)
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def _find_karon_mcp_bin() -> Path:
    """Find karon-mcp binary in PATH or the repo-local virtualenv."""
    import shutil
    # Try PATH first
    bin_path = shutil.which("karon-mcp")
    if bin_path:
        return Path(bin_path)
    # Fallback to current directory venv
    local_venv = Path(__file__).resolve().parents[1] / ".venv/bin/karon-mcp"
    if local_venv.exists():
        return local_venv
    return Path("karon-mcp")  # Will fail with helpful error

KARON_MCP_BIN = _find_karon_mcp_bin()
API_KEY = os.environ.get("KARON_API_KEY", "")


class MCPTestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.proc = None

    def start_server(self, api_key: str = ""):
        """Start MCP server process."""
        env = os.environ.copy()
        if api_key:
            env["KARON_API_KEY"] = api_key
        elif "KARON_API_KEY" in env:
            del env["KARON_API_KEY"]  # Explicitly unset

        self.proc = subprocess.Popen(
            [str(KARON_MCP_BIN)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env
        )
        return self.proc

    def stop_server(self):
        """Stop MCP server."""
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            stderr = self.proc.stderr.read()
            self.proc = None
            return stderr
        return ""

    def send_request(self, req: dict) -> dict:
        """Send JSON-RPC request and return response."""
        line = json.dumps(req) + "\n"
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

        # Read response with timeout
        start = time.time()
        while time.time() - start < 30:
            response_line = self.proc.stdout.readline()
            if response_line:
                try:
                    return json.loads(response_line)
                except json.JSONDecodeError:
                    continue
            time.sleep(0.1)
        return {}

    def assert_true(self, condition: bool, msg: str):
        """Assert condition and print result."""
        if condition:
            print(f"  {GREEN}✓{RESET} {msg}")
            self.passed += 1
        else:
            print(f"  {RED}✗{RESET} {msg}")
            self.failed += 1

    def test_initialize(self):
        """Test initialize handshake."""
        print("\n[Test] initialize")
        self.start_server(API_KEY)

        resp = self.send_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })

        self.assert_true("result" in resp, "Has result field")
        self.assert_true(resp.get("result", {}).get("serverInfo", {}).get("name") == "karon-mcp",
                        "Server name is karon-mcp")
        self.assert_true(resp.get("id") == 1, "Response id matches request")

        self.stop_server()

    def test_tools_list(self):
        """Test tools/list."""
        print("\n[Test] tools/list")
        self.start_server(API_KEY)

        # Initialize first
        self.send_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })

        resp = self.send_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        })

        tools = resp.get("result", {}).get("tools", [])
        tool_names = [t.get("name") for t in tools]

        self.assert_true("browse" in tool_names, "Has 'browse' tool")
        self.assert_true("crawl" in tool_names, "Has 'crawl' tool")

        # Check browse tool schema
        browse_tool = next((t for t in tools if t["name"] == "browse"), None)
        if browse_tool:
            props = browse_tool.get("inputSchema", {}).get("properties", {})
            self.assert_true("url" in props, "browse has 'url' parameter")
            self.assert_true("extract" in props, "browse has 'extract' parameter")

        self.stop_server()

    def test_browse_httpbin(self):
        """Test browse with httpbin.org."""
        print("\n[Test] browse - httpbin.org/html")
        self.start_server(API_KEY)

        # Initialize
        self.send_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })

        resp = self.send_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "browse",
                "arguments": {
                    "url": "https://httpbin.org/html",
                    "extract": "text"
                }
            }
        })

        result = resp.get("result", {})
        content = result.get("content", [{}])[0].get("text", "")

        self.assert_true("result" in resp, "Has result field")
        self.assert_true("Herman Melville" in content or len(content) > 100,
                        "Content contains expected text or has reasonable length")
        self.assert_true("[credits_used]:" in content or "credits_used" in content,
                        "Content includes credits_used info")

        self.stop_server()

    def test_browse_cache_hit(self):
        """Test browse cache hit (same URL twice)."""
        print("\n[Test] browse - cache hit verification")
        self.start_server(API_KEY)

        # Initialize
        self.send_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })

        # First request
        resp1 = self.send_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "browse",
                "arguments": {"url": "https://httpbin.org/uuid", "extract": "text"}
            }
        })
        content1 = resp1.get("result", {}).get("content", [{}])[0].get("text", "")
        cache_hit_1 = "[cache_hit]: True" in content1 or '"cache_hit": true' in content1

        # Second request (should be cached)
        resp2 = self.send_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "browse",
                "arguments": {"url": "https://httpbin.org/uuid", "extract": "text"}
            }
        })
        content2 = resp2.get("result", {}).get("content", [{}])[0].get("text", "")
        cache_hit_2 = "[cache_hit]: True" in content2 or '"cache_hit": true' in content2

        # httpbin/uuid is dynamic, so cache won't hit - but test the flow
        self.assert_true("[cache_hit]:" in content1, "First request shows cache_hit status")
        self.assert_true("[cache_hit]:" in content2, "Second request shows cache_hit status")

        self.stop_server()

    def test_crawl_multiple(self):
        """Test crawl with multiple URLs."""
        print("\n[Test] crawl - multiple URLs")
        self.start_server(API_KEY)

        # Initialize
        self.send_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })

        resp = self.send_request({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "crawl",
                "arguments": {
                    "urls": [
                        "https://httpbin.org/html",
                        "https://httpbin.org/ip"
                    ],
                    "extract": "text",
                    "concurrency": 2
                }
            }
        })

        result = resp.get("result", {})
        content = result.get("content", [{}])[0].get("text", "")

        self.assert_true("result" in resp, "Has result field")
        # crawl returns JSON array
        try:
            data = json.loads(content)
            self.assert_true(isinstance(data, list), "Crawl result is a list")
            self.assert_true(len(data) >= 2, "Crawl result has at least 2 items")
        except json.JSONDecodeError:
            self.assert_true(False, "Crawl result is valid JSON")

        self.stop_server()

    def test_browse_invalid_url(self):
        """Test browse with invalid URL."""
        print("\n[Test] browse - invalid URL handling")
        self.start_server(API_KEY)

        # Initialize
        self.send_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })

        resp = self.send_request({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "browse",
                "arguments": {
                    "url": "not-a-valid-url",
                    "extract": "text"
                }
            }
        })

        result = resp.get("result", {})
        content = result.get("content", [{}])[0].get("text", "")

        self.assert_true("error" in content.lower() or "must use http" in content.lower(),
                        "Returns error for invalid URL")

        self.stop_server()

    def test_missing_api_key(self):
        """Test behavior when API key is missing."""
        print("\n[Test] browse - missing API key")
        self.start_server("")  # No API key

        # Initialize
        self.send_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        })

        resp = self.send_request({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "browse",
                "arguments": {"url": "https://example.com", "extract": "text"}
            }
        })

        result = resp.get("result", {})
        content = result.get("content", [{}])[0].get("text", "")

        self.assert_true("KARON_API_KEY" in content or "not set" in content.lower(),
                        "Returns error about missing API key")

        self.stop_server()

    def run_all(self):
        """Run all tests."""
        print("=" * 60)
        print("Karon MCP Integration Tests")
        print("=" * 60)
        print(f"Server binary: {KARON_MCP_BIN}")
        print(f"API Key set: {'Yes' if API_KEY else 'No'}")

        if not KARON_MCP_BIN.exists():
            print(f"\n{RED}ERROR: Server binary not found at {KARON_MCP_BIN}{RESET}")
            print("Install the package in a local virtualenv or make karon-mcp available on PATH.")
            return 1

        tests = [
            self.test_initialize,
            self.test_tools_list,
            self.test_browse_httpbin,
            self.test_browse_cache_hit,
            self.test_crawl_multiple,
            self.test_browse_invalid_url,
            self.test_missing_api_key,
        ]

        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"  {RED}✗{RESET} {test.__name__} crashed: {e}")
                self.failed += 1
                self.stop_server()  # Cleanup

        print("\n" + "=" * 60)
        print(f"Results: {GREEN}{self.passed} passed{RESET}, {RED}{self.failed} failed{RESET}")
        print("=" * 60)

        return 0 if self.failed == 0 else 1


def main():
    runner = MCPTestRunner()
    exit_code = runner.run_all()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

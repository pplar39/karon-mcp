# karon-mcp

MCP server for the [Karon API](https://karonlabs.net/api/). Retrieve web content directly from Claude, Cursor, VS Code, or any MCP-compatible client.

Karon MCP 1.4.3 is the supported public release.

## Features

- Retrieve a single page as markdown, text, or HTML
- Retrieve multiple known URLs in one request
- Extract structured JSON from a page with an optional schema or prompt
- Save and compare page snapshots
- Check account credits and public pricing from your MCP client
- Works with Claude, Cursor, VS Code, and other MCP-compatible clients

## Quick Start

### 1. Get your API key

Sign up at [karonlabs.net/api/signup.html](https://karonlabs.net/api/signup.html).

### 2. Install

**Claude Desktop / Claude Code** — add to your MCP config (`claude_desktop_config.json` or `.mcp.json`):

```json
{
  "mcpServers": {
    "karon": {
      "command": "uvx",
      "args": ["karon-mcp"],
      "env": {
        "KARON_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

> `uvx` auto-fetches the latest version from PyPI on every run. No manual updates needed.

**Cursor** — go to Settings > MCP Servers > Add, then use the same config above.

**VS Code** — add this to your User Settings (JSON), or to `.vscode/mcp.json` in a workspace:

```json
{
  "mcp": {
    "inputs": [
      {
        "type": "promptString",
        "id": "apiKey",
        "description": "Karon API Key",
        "password": true
      }
    ],
    "servers": {
      "karon": {
        "command": "uvx",
        "args": ["karon-mcp"],
        "env": {
          "KARON_API_KEY": "${input:apiKey}"
        }
      }
    }
  }
}
```

**Manual install** (if you prefer pip):

```bash
pip install karon-mcp
```

### 3. Use

Once installed, eleven tools become available in your MCP client. The original `browse` and `crawl` tools are included alongside the expanded API surface.

## How to Choose a Tool

- If you need one page: use `browse` or `scrape`
- If you need several known URLs: use `crawl` or `batch_scrape`
- If you need structured data from one page: use `extract`
- If you need fetched page data: use `fetch`
- If you need to track changes over time: use `watch_snapshot`, `watch_diff`, and `watch_list`
- If you need account or pricing information: use `credits` or `pricing`

## Quick Reference

| Tool | Best for | Notes |
|------|----------|-------|
| `browse` | Single URL content | Simple markdown, text, or HTML retrieval |
| `crawl` | Multiple URLs | Compatibility-friendly multi-URL retrieval |
| `scrape` | Single URL with format options | Use when you want explicit output formats |
| `fetch` | Fetched page data | Use when you need the fetched response payload |
| `extract` | Structured JSON | Use schema or prompt when you know the fields |
| `batch_scrape` | Multiple known URLs | Use for batch retrieval workflows |
| `watch_snapshot` | Save current page state | Pair with `watch_diff` |
| `watch_diff` | Compare page state | Requires a prior saved snapshot |
| `watch_list` | List saved watch targets | Requires `KARON_API_KEY` |
| `credits` | Account usage | Requires `KARON_API_KEY` |
| `pricing` | Public pricing | Does not require account credentials |

#### `browse` — Fetch a single URL

```
browse(url="https://example.com", extract="markdown", readability=True)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | string | required | Target URL (http/https) |
| `extract` | string | `"markdown"` | Output format: `"markdown"`, `"text"`, or `"html"` |
| `readability` | bool | `True` | `True` = main content only, `False` = full page |

#### `crawl` — Fetch multiple URLs concurrently

```
crawl(urls=["https://a.com", "https://b.com"], extract="markdown", concurrency=3)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `urls` | list[string] | required | Up to 20 URLs |
| `extract` | string | `"markdown"` | Output format: `"markdown"` or `"text"` |
| `readability` | bool | `True` | Main content only |
| `concurrency` | int | `3` | Parallel requests (1-5) |

#### Additional tools

| Tool | Purpose |
|------|---------|
| `scrape` | Retrieve one URL with format options |
| `fetch` | Retrieve raw page data |
| `extract` | Retrieve structured JSON data |
| `batch_scrape` | Retrieve multiple URLs in one request |
| `watch_snapshot` | Save a snapshot for one URL |
| `watch_diff` | Compare a URL with its previous saved snapshot |
| `watch_list` | List saved watch targets |
| `credits` | Show account credit and tier information |
| `pricing` | Show public pricing information |

### Credits

| Method | Cost |
|--------|------|
| Cache hit | 1 credit |
| Cache miss | 10 credits |

See [pricing](https://karonlabs.net/api/pricing.html) for current free tier and paid tier details.

## Configuration

The only required configuration is the `KARON_API_KEY` environment variable. Get yours at [karonlabs.net/api/signup.html](https://karonlabs.net/api/signup.html).

## Common Mistakes

- Use `batch_scrape` or `crawl` for multiple URLs instead of calling a single-page tool repeatedly.
- Use `extract` when you need specific fields instead of asking for a full page and parsing it manually.
- Keep `KARON_API_KEY` in the MCP client environment, not in prompts or source files.
- Use `uvx --refresh karon-mcp` if your client appears to run an older cached version.

## Troubleshooting

- If the server starts but tools fail, confirm `KARON_API_KEY` is set in the MCP client config.
- If a client still shows an old tool list, restart the client and refresh the MCP server.
- If you installed with pip, run `pip install --upgrade karon-mcp`.
- For `uvx`, run `uvx --refresh karon-mcp` to force a fresh install.

## Updating

If you're using `uvx` (recommended), updates are automatic — every run fetches the latest version.

If you installed with pip:

```bash
pip install --upgrade karon-mcp
```

## Links

- [API Documentation](https://karonlabs.net/api/docs.html)
- [Pricing](https://karonlabs.net/api/pricing.html)

## License

MIT

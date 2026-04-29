"""Entry point for `python -m karon_mcp` and `uvx karon-mcp`."""
from karon_mcp.server import mcp


def main():
    mcp.run()


if __name__ == "__main__":
    main()

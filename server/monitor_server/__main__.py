from __future__ import annotations

import argparse

import uvicorn

from .app import create_app
from .config import load_server_config


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the monitor server.")
    parser.add_argument("--config", default="server.yaml", help="Path to server YAML config.")
    parser.add_argument("--host", help="Override bind host.")
    parser.add_argument("--port", type=int, help="Override bind port.")
    args = parser.parse_args()

    config = load_server_config(args.config)
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port)


if __name__ == "__main__":
    main()

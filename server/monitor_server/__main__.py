from __future__ import annotations

import argparse

import uvicorn

from .app import create_app
from .config import load_server_config
from .doctor import format_doctor_report, run_config_doctor
from .security import hash_secret


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the monitor server.")
    parser.add_argument("--config", default="server.yaml", help="Path to server YAML config.")
    parser.add_argument("--host", help="Override bind host.")
    parser.add_argument("--port", type=int, help="Override bind port.")
    parser.add_argument("--hash-secret", help="Print an Argon2id hash for an admin password or agent token.")
    parser.add_argument("--doctor", action="store_true", help="Validate config and exit without starting the server.")
    args = parser.parse_args()

    if args.hash_secret:
        print(hash_secret(args.hash_secret))
        return

    try:
        config = load_server_config(args.config)
    except ValueError as exc:
        if args.doctor:
            print("Config doctor: error")
            print(f"[error] config_load: {exc}")
            raise SystemExit(1) from exc
        raise
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port

    if args.doctor:
        report = run_config_doctor(config)
        print(format_doctor_report(report))
        raise SystemExit(1 if report["status"] == "error" else 0)

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port)


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import asyncio
import logging

from .client import MonitorAgent
from .config import load_agent_config


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the monitor agent.")
    parser.add_argument("--config", default="agent.yaml", help="Path to agent YAML config.")
    parser.add_argument("--log-level", default="INFO", help="Python logging level.")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    config = load_agent_config(args.config)
    agent = MonitorAgent(config)
    asyncio.run(agent.run_forever())


if __name__ == "__main__":
    main()

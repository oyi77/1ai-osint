"""Node and master bot commands."""

from __future__ import annotations

import asyncio
import json
import os
import socket

import typer

from ..app import app


@app.command()
def node(
    action: str = typer.Argument(..., help="Action: start, status"),
    node_id: str = typer.Option(socket.gethostname(), help="Node identifier"),
    master_chat_id: str = typer.Option("", help="Master Telegram chat ID"),
    api_port: int = typer.Option(8420, help="HTTP API port"),
) -> None:
    """Run as a worker node, connecting to master via Telegram."""

    async def _run_node() -> None:
        token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        chat_id = master_chat_id or os.getenv("MASTER_CHAT_ID", "")

        if not token or not chat_id:
            typer.echo("Error: TELEGRAM_BOT_TOKEN and MASTER_CHAT_ID required", err=True)
            raise typer.Exit(1)

        from src.modules.node.agent import NodeAgent

        agent = NodeAgent(
            node_id=node_id,
            telegram_token=token,
            master_chat_id=chat_id,
        )

        if action == "start":
            typer.echo(f"Starting node '{node_id}'...", err=True)
            await agent.start()
        elif action == "status":
            status = agent.get_status()
            typer.echo(json.dumps(status.to_dict(), indent=2))
        else:
            typer.echo(f"Unknown action: {action}", err=True)
            raise typer.Exit(1)

    asyncio.run(_run_node())


@app.command()
def master(
    action: str = typer.Argument(..., help="Action: start, status"),
    allowed_chat_ids: str = typer.Option("", help="Comma-separated allowed Telegram chat IDs"),
) -> None:
    """Run as the master bot, controlling all nodes via Telegram."""

    async def _run_master() -> None:
        token = os.getenv("TELEGRAM_BOT_TOKEN", "")

        if not token:
            typer.echo("Error: TELEGRAM_BOT_TOKEN required", err=True)
            raise typer.Exit(1)

        chat_ids = [c.strip() for c in allowed_chat_ids.split(",") if c.strip()]
        if not chat_ids:
            chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
            if chat_id:
                chat_ids = [chat_id]

        from src.modules.node.master import MasterBot

        bot = MasterBot(telegram_token=token, allowed_chat_ids=chat_ids)

        if action == "start":
            typer.echo("Starting master bot...", err=True)
            await bot.start()
        elif action == "status":
            typer.echo(f"Nodes: {len(bot.nodes)}")
            for nid, node in bot.nodes.items():
                typer.echo(f"  {nid}: {node.hostname} ({node.ip})")
        else:
            typer.echo(f"Unknown action: {action}", err=True)
            raise typer.Exit(1)

    asyncio.run(_run_master())

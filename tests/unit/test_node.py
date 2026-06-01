"""Tests for the master-node orchestration module."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.modules.node.protocol import (
    NodeMessage, NodeStatus, MessageType, CommandType,
)


class TestProtocol:
    def test_message_serialize(self):
        msg = NodeMessage(msg_type=MessageType.REGISTER, node_id="test-node", payload={"hostname": "vps1"})
        text = msg.to_telegram()
        data = json.loads(text)
        assert data["t"] == "register"
        assert data["n"] == "test-node"
        assert data["p"]["hostname"] == "vps1"

    def test_message_deserialize(self):
        text = json.dumps({"t": "heartbeat", "n": "node1", "p": {"cpu": 5.0}, "ts": "2026-01-01"})
        msg = NodeMessage.from_telegram(text)
        assert msg is not None
        assert msg.msg_type == MessageType.HEARTBEAT
        assert msg.node_id == "node1"
        assert msg.payload["cpu"] == 5.0

    def test_message_deserialize_invalid(self):
        assert NodeMessage.from_telegram("not json") is None
        assert NodeMessage.from_telegram("{}") is None

    def test_node_status_to_dict(self):
        status = NodeStatus(
            node_id="test", hostname="host", ip="1.2.3.4", version="abc123",
            scanner_running=True, scan_count=42,
        )
        d = status.to_dict()
        assert d["node_id"] == "test"
        assert d["scanner_running"] is True
        assert d["scan_count"] == 42

    def test_message_type_values(self):
        assert MessageType.REGISTER.value == "register"
        assert MessageType.HEARTBEAT.value == "heartbeat"
        assert CommandType.START.value == "start"
        assert CommandType.SYNC.value == "sync"


class TestNodeAgent:
    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    def test_init(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        assert agent.node_id == "test-node"
        assert agent.role == "worker"
        assert agent.heartbeat_interval == 30

    def test_get_ip(self):
        from src.modules.node.agent import NodeAgent
        ip = NodeAgent._get_ip()
        assert isinstance(ip, str)

    def test_get_version(self):
        from src.modules.node.agent import NodeAgent
        version = NodeAgent._get_version()
        assert isinstance(version, str)

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    def test_get_status(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        status = agent._get_status()
        assert status.node_id == "test-node"
        assert status.hostname == "test-host"
        assert status.scanner_running is False

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_stop_when_no_scanner(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        await agent.stop()
        assert agent._running is False

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_handle_command_status(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        result = await agent.handle_command(CommandType.STATUS, {})
        assert "node_id" in result
        assert result["node_id"] == "test-node"


class TestMasterBot:
    def test_init(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        assert bot.telegram_token == "fake-token"
        assert bot.allowed_chat_ids == ["123"]
        assert len(bot.nodes) == 0

    def test_format_uptime(self):
        from src.modules.node.master import MasterBot
        assert "s" in MasterBot._format_uptime(30)
        assert "m" in MasterBot._format_uptime(300)
        assert "h" in MasterBot._format_uptime(7200)
        assert "d" in MasterBot._format_uptime(172800)

    @pytest.mark.asyncio
    async def test_stop(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token")
        bot._running = True
        await bot.stop()
        assert bot._running is False

    @pytest.mark.asyncio
    async def test_handle_node_register(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        msg = NodeMessage(
            msg_type=MessageType.REGISTER,
            node_id="vps1",
            payload={"hostname": "prod", "ip": "5.189.138.144", "version": "abc", "role": "worker"},
        )
        with patch.object(bot, "_send_message", new_callable=AsyncMock):
            await bot._handle_node_message(msg)
        assert "vps1" in bot.nodes
        assert bot.nodes["vps1"].hostname == "prod"

    @pytest.mark.asyncio
    async def test_handle_node_heartbeat(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token")
        bot.nodes["vps1"] = NodeStatus(
            node_id="vps1", hostname="prod", ip="1.2.3.4", version="abc",
        )
        msg = NodeMessage(
            msg_type=MessageType.HEARTBEAT,
            node_id="vps1",
            payload={"scanner_running": True, "scan_count": 10, "uptime_sec": 100, "memory_mb": 512, "cpu_percent": 2.5},
        )
        await bot._handle_node_message(msg)
        assert bot.nodes["vps1"].scanner_running is True
        assert bot.nodes["vps1"].scan_count == 10

    @pytest.mark.asyncio
    async def test_handle_command_help(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_help("123", "")
            mock_send.assert_called_once()
            assert "help" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_handle_command_nodes_empty(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_nodes("123", "")
            mock_send.assert_called_once()
            assert "no nodes" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_handle_command_start_no_node(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_start("123", "")
            mock_send.assert_called_once()
            assert "usage" in mock_send.call_args[0][1].lower()


class TestNodeAgentAdvanced:
    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_send_to_master(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        msg = NodeMessage(msg_type=MessageType.HEARTBEAT, node_id="test-node", payload={"test": True})
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            await agent._send_to_master(msg)
        mock_client.post.assert_called_once()

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_report_result(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        with patch.object(agent, "_send_to_master", new_callable=AsyncMock) as mock_send:
            await agent.report_result({"leaks": 5, "keys": 2})
        mock_send.assert_called_once()

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_cmd_stop_scanner_not_running(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        result = await agent._cmd_stop_scanner()
        assert result["status"] == "not_running"

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_cmd_start_scanner_already_running(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        mock_proc = MagicMock()
        mock_proc.returncode = None
        agent._scanner_process = mock_proc
        result = await agent._cmd_start_scanner({})
        assert result["status"] == "already_running"


class TestMasterBotAdvanced:
    @pytest.mark.asyncio
    async def test_send_to(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token")
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.master.httpx.AsyncClient", return_value=mock_client):
            await bot._send_to("12345", "test message")
        mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_message_broadcast(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["111", "222"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._send_message("broadcast")
        assert mock_send.call_count == 2

    @pytest.mark.asyncio
    async def test_handle_command_unknown(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._handle_command("123", "/fakecmd")
        assert "unknown" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_cmd_nodes_with_nodes(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        bot.nodes["vps1"] = NodeStatus(
            node_id="vps1", hostname="prod", ip="5.189.138.144", version="abc",
            scanner_running=True, scan_count=42, uptime_sec=3600, memory_mb=512, cpu_percent=2.5,
        )
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_nodes("123", "")
        text = mock_send.call_args[0][1]
        assert "vps1" in text
        assert "prod" in text

    @pytest.mark.asyncio
    async def test_cmd_status_not_found(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_status("123", "nonexistent")
        assert "not found" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_cmd_deploy_no_nodes(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_deploy("123", "")
        assert "no nodes" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_handle_node_result(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        msg = NodeMessage(
            msg_type=MessageType.RESULT,
            node_id="vps1",
            payload={"leaks": 5, "keys": 2, "funded": 0},
        )
        with patch.object(bot, "_send_message", new_callable=AsyncMock) as mock_send:
            await bot._handle_node_message(msg)
        assert "vps1" in mock_send.call_args[0][0]

    @pytest.mark.asyncio
    async def test_handle_node_error(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        msg = NodeMessage(
            msg_type=MessageType.ERROR,
            node_id="vps1",
            payload={"error": "OOM killed"},
        )
        with patch.object(bot, "_send_message", new_callable=AsyncMock) as mock_send:
            await bot._handle_node_message(msg)
        assert "OOM" in mock_send.call_args[0][0]

    @pytest.mark.asyncio
    async def test_handle_message_unauthorized(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._handle_message("999", "/nodes")
        assert "unauthorized" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_handle_node_heartbeat_new_node(self):
        """Heartbeat for unknown node should be silently ignored."""
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token")
        msg = NodeMessage(
            msg_type=MessageType.HEARTBEAT,
            node_id="unknown",
            payload={"scanner_running": True, "scan_count": 10},
        )
        await bot._handle_node_message(msg)
        assert "unknown" not in bot.nodes


class TestNodeAgentDeep:
    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_heartbeat(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        with patch.object(agent, "_send_to_master", new_callable=AsyncMock) as mock_send:
            await agent._heartbeat()
        mock_send.assert_called_once()
        call_msg = mock_send.call_args[0][0]
        assert call_msg.msg_type == MessageType.HEARTBEAT
        assert "scanner_running" in call_msg.payload

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_cmd_sync(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"Already up to date.\n", b""))
        with patch("src.modules.node.agent.asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("src.modules.node.agent.asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
                mock_wait.return_value = (b"Already up to date.\n", b"")
                result = await agent._cmd_sync()
        assert result["status"] == "synced"

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_cmd_scan_once(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"scan output", b""))
        with patch("src.modules.node.agent.asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("src.modules.node.agent.asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
                mock_wait.return_value = (b"scan output", b"")
                result = await agent._cmd_scan_once({})
        assert result["status"] == "completed"
        assert agent._scan_count == 1

    @patch("src.modules.node.agent.socket.gethostname", return_value="test-host")
    @pytest.mark.asyncio
    async def test_handle_command_restart(self, mock_hostname):
        from src.modules.node.agent import NodeAgent
        agent = NodeAgent(
            node_id="test-node",
            telegram_token="fake-token",
            master_chat_id="12345",
        )
        with patch.object(agent, "_cmd_stop_scanner", new_callable=AsyncMock, return_value={"status": "stopped"}):
            with patch.object(agent, "_cmd_start_scanner", new_callable=AsyncMock, return_value={"status": "started"}):
                result = await agent.handle_command(CommandType.RESTART, {})
        assert "started" in str(result)


class TestMasterBotDeep:
    @pytest.mark.asyncio
    async def test_handle_message_node_message(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        msg = NodeMessage(
            msg_type=MessageType.REGISTER,
            node_id="vps1",
            payload={"hostname": "prod", "ip": "1.2.3.4", "version": "abc", "role": "worker"},
        )
        with patch.object(bot, "_handle_node_message", new_callable=AsyncMock) as mock_handle:
            await bot._handle_message("123", f"[1ai-node]\n{msg.to_telegram()}")
        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_message_text_command(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_handle_command", new_callable=AsyncMock) as mock_handle:
            await bot._handle_message("123", "/help")
        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_message_plain_text(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_handle_command", new_callable=AsyncMock) as mock_handle:
            await bot._handle_message("123", "just plain text")
        mock_handle.assert_not_called()

    @pytest.mark.asyncio
    async def test_cmd_restart_usage(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_restart("123", "")
        assert "usage" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_cmd_sync_usage(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_sync("123", "")
        assert "usage" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_cmd_scan_usage(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_scan("123", "")
        assert "usage" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_cmd_config_usage(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._cmd_config("123", "badformat")
        assert "usage" in mock_send.call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_send_command_to_node_not_found(self):
        from src.modules.node.master import MasterBot
        bot = MasterBot(telegram_token="fake-token", allowed_chat_ids=["123"])
        with patch.object(bot, "_send_to", new_callable=AsyncMock) as mock_send:
            await bot._send_command_to_node("nonexistent", CommandType.START, {}, "123")
        assert "not found" in mock_send.call_args[0][1].lower()


# ---------------------------------------------------------------------------
# Database module tests
# ---------------------------------------------------------------------------
class TestDB:
    def test_hash_key(self):
        from src.modules.node.db import hash_key
        h = hash_key("test_key_12345")
        assert len(h) == 32
        assert h == hash_key("test_key_12345")  # deterministic

    def test_hash_key_different(self):
        from src.modules.node.db import hash_key
        h1 = hash_key("key1")
        h2 = hash_key("key2")
        assert h1 != h2


# ---------------------------------------------------------------------------
# Master API tests
# ---------------------------------------------------------------------------
class TestMasterAPI:
    def _make_client(self):
        from src.modules.node.master_api import app
        from fastapi.testclient import TestClient
        return TestClient(app)

    def test_health_endpoint(self):
        client = self._make_client()
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @patch("src.modules.node.db.get_stats", new_callable=AsyncMock)
    def test_stats_endpoint(self, mock_stats):
        mock_stats.return_value = {"seen_keys": 0, "raw_leaks": 0, "extracted_keys": 0, "funded_wallets": 0, "swept_wallets": 0, "active_nodes": 0}
        client = self._make_client()
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        assert "seen_keys" in resp.json()

    @patch("src.modules.node.db.get_audit_trail", new_callable=AsyncMock)
    def test_audit_endpoint(self, mock_audit):
        mock_audit.return_value = []
        client = self._make_client()
        resp = client.get("/api/audit")
        assert resp.status_code == 200
        assert "events" in resp.json()

    @patch("src.modules.node.db.get_all_heartbeats", new_callable=AsyncMock)
    def test_nodes_endpoint(self, mock_hb):
        mock_hb.return_value = []
        client = self._make_client()
        resp = client.get("/api/nodes")
        assert resp.status_code == 200
        assert "nodes" in resp.json()


# ---------------------------------------------------------------------------
# NodeAgent API sync tests
# ---------------------------------------------------------------------------
class TestNodeAgentAPISync:
    def _make_agent(self):
        from src.modules.node.agent import NodeAgent
        return NodeAgent(
            node_id="test-node",
            telegram_token="fake",
            master_chat_id="123",
            master_api_url="http://localhost:8420",
        )

    @pytest.mark.asyncio
    async def test_sync_seen_keys_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"bloom": "abc123|def456", "count": 2}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            keys = await agent.sync_seen_keys()
        assert len(keys) == 2

    @pytest.mark.asyncio
    async def test_sync_seen_keys_error(self):
        agent = self._make_agent()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("connection failed"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            keys = await agent.sync_seen_keys()
        assert keys == set()

    @pytest.mark.asyncio
    async def test_report_keys_api_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"recorded": 2}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.report_keys_api([{"key_hash": "abc", "key_type": "hex", "source": "test"}])
        assert result == 2

    @pytest.mark.asyncio
    async def test_acquire_sweep_lock_success(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.acquire_sweep_lock("0x123")
        assert result is True

    @pytest.mark.asyncio
    async def test_acquire_sweep_lock_denied(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 409
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            result = await agent.acquire_sweep_lock("0x123")
        assert result is False

    @pytest.mark.asyncio
    async def test_report_sweep_api(self):
        agent = self._make_agent()
        resp = MagicMock()
        resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.modules.node.agent.httpx.AsyncClient", return_value=mock_client):
            await agent.report_sweep_api("0x123", "tx_hash")

    def test_is_key_seen(self):
        agent = self._make_agent()
        agent._seen_keys = {"abc123"}
        assert agent.is_key_seen("test") is False  # different hash

    def test_is_key_seen_empty(self):
        agent = self._make_agent()
        assert agent.is_key_seen("test") is False


# ---------------------------------------------------------------------------
# DB module additional tests
# ---------------------------------------------------------------------------
class TestDBModule:
    def test_hash_key_consistency(self):
        from src.modules.node.db import hash_key
        assert hash_key("hello") == hash_key("hello")
        assert hash_key("hello") != hash_key("world")

    def test_hash_key_length(self):
        from src.modules.node.db import hash_key
        for key in ["a", "ab", "abcdefghijklmnop"]:
            assert len(hash_key(key)) == 32

    def test_hash_key_hex(self):
        from src.modules.node.db import hash_key
        h = hash_key("test")
        # Should be valid hex
        int(h, 16)


# ---------------------------------------------------------------------------
# Master API endpoint tests
# ---------------------------------------------------------------------------
class TestMasterAPIEndpoints:
    def _make_client(self):
        from src.modules.node.master_api import app
        from fastapi.testclient import TestClient
        return TestClient(app)

    @patch("src.modules.node.db.is_key_seen", new_callable=AsyncMock)
    @patch("src.modules.node.db.mark_key_seen", new_callable=AsyncMock)
    def test_report_keys_new(self, mock_mark, mock_seen):
        mock_seen.return_value = False
        mock_mark.return_value = None
        client = self._make_client()
        resp = client.post("/api/keys", json={
            "node_id": "test",
            "keys": [{"key_hash": "abc123", "key_type": "hex", "source": "reddit"}],
        })
        assert resp.status_code == 200
        assert resp.json()["recorded"] == 1

    @patch("src.modules.node.db.is_key_seen", new_callable=AsyncMock)
    def test_report_keys_seen(self, mock_seen):
        mock_seen.return_value = True
        client = self._make_client()
        resp = client.post("/api/keys", json={
            "node_id": "test",
            "keys": [{"key_hash": "abc123", "key_type": "hex", "source": "reddit"}],
        })
        assert resp.status_code == 200
        assert resp.json()["recorded"] == 0

    @patch("src.modules.node.db.get_seen_keys_bloom", new_callable=AsyncMock)
    def test_get_seen(self, mock_bloom):
        mock_bloom.return_value = b"abc|def|ghi"
        client = self._make_client()
        resp = client.get("/api/seen")
        assert resp.status_code == 200
        assert resp.json()["count"] == 3

    @patch("src.modules.node.db.acquire_sweep_lock", new_callable=AsyncMock)
    def test_acquire_lock_success(self, mock_lock):
        mock_lock.return_value = True
        client = self._make_client()
        resp = client.post("/api/locks", json={
            "address": "0x123",
            "node_id": "test",
            "ttl_seconds": 300,
        })
        assert resp.status_code == 200

    @patch("src.modules.node.db.acquire_sweep_lock", new_callable=AsyncMock)
    def test_acquire_lock_denied(self, mock_lock):
        mock_lock.return_value = False
        client = self._make_client()
        resp = client.post("/api/locks", json={
            "address": "0x123",
            "node_id": "test",
            "ttl_seconds": 300,
        })
        assert resp.status_code == 409

    @patch("src.modules.node.db.record_heartbeat", new_callable=AsyncMock)
    def test_heartbeat(self, mock_hb):
        mock_hb.return_value = None
        client = self._make_client()
        resp = client.post("/api/heartbeat", json={
            "node_id": "test",
            "status": {"hostname": "host", "cpu": 50},
        })
        assert resp.status_code == 200

    @patch("src.modules.node.db.mark_swept", new_callable=AsyncMock)
    def test_report_sweep(self, mock_sweep):
        mock_sweep.return_value = None
        client = self._make_client()
        resp = client.post("/api/sweep", json={
            "address": "0x123",
            "node_id": "test",
            "sweep_tx": "tx_hash",
        })
        assert resp.status_code == 200

    @patch("src.modules.node.db.get_assigned_sources", new_callable=AsyncMock)
    def test_get_sources_assigned(self, mock_src):
        mock_src.return_value = ["reddit", "github"]
        client = self._make_client()
        resp = client.get("/api/sources?node_id=test")
        assert resp.status_code == 200
        assert resp.json()["sources"] == ["reddit", "github"]


# ---------------------------------------------------------------------------
# DB mock tests for remaining functions
# ---------------------------------------------------------------------------
class TestDBMocked:
    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_init_db(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import init_db
        await init_db()
        mock_conn.execute.assert_called_once()

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_record_heartbeat(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import record_heartbeat
        await record_heartbeat("test", {"hostname": "h", "ip": "1.2.3.4", "version": "v"})
        mock_conn.execute.assert_called_once()

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_assign_sources(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import assign_sources
        await assign_sources("test", ["reddit", "github"])
        mock_conn.execute.assert_called_once()

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_record_raw_leak(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": 1})
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import record_raw_leak
        result = await record_raw_leak("reddit", "http://test.com", "hash123", "node1")
        assert result == 1

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_record_funded_wallet(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import record_funded_wallet
        await record_funded_wallet("0x123", "Ethereum", 1.5, "key_hash")
        mock_conn.execute.assert_called_once()


# ---------------------------------------------------------------------------
# Protocol additional tests
# ---------------------------------------------------------------------------
class TestProtocolExtra:
    def test_message_types(self):
        from src.modules.node.protocol import MessageType
        assert MessageType.REGISTER.value == "register"
        assert MessageType.HEARTBEAT.value == "heartbeat"
        assert MessageType.COMMAND.value == "command"

    def test_command_types(self):
        from src.modules.node.protocol import CommandType
        assert CommandType.START.value == "start"
        assert CommandType.STOP.value == "stop"
        assert CommandType.SYNC.value == "sync"

    def test_node_status_defaults(self):
        from src.modules.node.protocol import NodeStatus
        s = NodeStatus(node_id="x", hostname="h", ip="1.1.1.1", version="v")
        assert s.role == "worker"
        assert s.scanner_running is False
        assert s.scan_count == 0
        assert s.errors == []

    def test_node_message_roundtrip(self):
        from src.modules.node.protocol import NodeMessage, MessageType
        msg = NodeMessage(msg_type=MessageType.RESULT, node_id="n1", payload={"found": 5})
        text = msg.to_telegram()
        parsed = NodeMessage.from_telegram(text)
        assert parsed.node_id == "n1"
        assert parsed.payload["found"] == 5


# ---------------------------------------------------------------------------
# DB comprehensive mocked tests
# ---------------------------------------------------------------------------
class TestDBComprehensive:
    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_close_pool(self, mock_pool):
        import src.modules.node.db as db_mod
        db_mod._pool = MagicMock()
        db_mod._pool.close = AsyncMock()
        await db_mod.close_pool()
        assert db_mod._pool is None

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_is_key_seen_true(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=(1,))
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import is_key_seen
        result = await is_key_seen("abc")
        assert result is True

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_is_key_seen_false(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import is_key_seen
        result = await is_key_seen("abc")
        assert result is False

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_mark_key_seen(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import mark_key_seen
        await mark_key_seen("hash", "hex", "reddit", "node1")
        mock_conn.execute.assert_called_once()

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_get_seen_keys_bloom(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"key_hash": "a"}, {"key_hash": "b"}])
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import get_seen_keys_bloom
        result = await get_seen_keys_bloom()
        assert b"a" in result
        assert b"b" in result

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_get_assigned_sources(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"sources": ["reddit", "github"]})
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import get_assigned_sources
        result = await get_assigned_sources("test")
        assert result == ["reddit", "github"]

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_get_assigned_sources_empty(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import get_assigned_sources
        result = await get_assigned_sources("test")
        assert result == []

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_get_all_heartbeats(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"node_id": "n1"}, {"node_id": "n2"}])
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import get_all_heartbeats
        result = await get_all_heartbeats()
        assert len(result) == 2

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_get_stats(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=0)
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import get_stats
        result = await get_stats()
        assert "seen_keys" in result
        assert "funded_wallets" in result

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_get_audit_trail(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"event_type": "leak"}])
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import get_audit_trail
        result = await get_audit_trail(10)
        assert len(result) == 1

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_record_extracted_key(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import record_extracted_key
        await record_extracted_key("hash", "hex", {"ETH": "0x123"}, 1, "node1")
        mock_conn.execute.assert_called_once()

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_record_balance_check(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import record_balance_check
        await record_balance_check("0x123", "ETH", 1.5, "hash", "node1")
        mock_conn.execute.assert_called_once()

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_mark_swept(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import mark_swept
        await mark_swept("0x123", "tx_hash")
        mock_conn.execute.assert_called_once()

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_get_unswept_wallets(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"address": "0x123", "swept": False}])
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import get_unswept_wallets
        result = await get_unswept_wallets()
        assert len(result) == 1

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_acquire_sweep_lock(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"node_id": "test"})
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import acquire_sweep_lock
        result = await acquire_sweep_lock("0x123", "test", 300)
        assert result is True

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_release_sweep_lock(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import release_sweep_lock
        await release_sweep_lock("0x123", "test")
        mock_conn.execute.assert_called_once()

    @patch("src.modules.node.db.get_pool", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_bulk_mark_seen(self, mock_pool):
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock()
        mock_acquire = MagicMock()
        mock_acquire.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquire.__aexit__ = AsyncMock(return_value=False)
        mock_pool.return_value = MagicMock(acquire=MagicMock(return_value=mock_acquire))
        from src.modules.node.db import bulk_mark_seen
        await bulk_mark_seen([{"key_hash": "a", "key_type": "hex", "source": "r", "node_id": "n"}])
        mock_conn.executemany.assert_called_once()

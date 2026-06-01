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

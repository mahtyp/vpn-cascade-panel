#!/usr/bin/env python3
"""Регрессии тайм-аутов и итогов операций (без реальных SSH/VPS)."""
import ast
import concurrent.futures as cf
import contextlib
import io
import ipaddress
import json
import re
import shlex
import subprocess
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import fw
import govblock
from provision import Job, Provisioner, Stop
from ssh_output import read_output

ROOT = Path(__file__).resolve().parent.parent


def dash_method(name):
    """Загружаем оригинальный метод Dash без запуска панели и открытия порта."""
    module = ast.parse((ROOT / "dash.py").read_text(encoding="utf-8"))
    dash = next(x for x in module.body if isinstance(x, ast.ClassDef) and x.name == "Dash")
    method = next(x for x in dash.body if isinstance(x, ast.FunctionDef) and x.name == name)
    cls = ast.ClassDef(name="RuntimeDash", bases=[], keywords=[], body=[method],
                       decorator_list=[], type_params=[])
    code = compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])),
                   "dash.py", "exec")
    namespace = {"re": re, "cf": cf, "ipaddress": ipaddress, "shlex": shlex, "urlparse": urlparse,
                 "CHECK_URL": "https://ifconfig.me", "CHECK_URL_IPV4": "https://api.ipify.org",
                 "time": types.SimpleNamespace(sleep=lambda _: None, monotonic=time.monotonic,
                                                        localtime=time.localtime, strftime=time.strftime),
                 "now": lambda: 1000, "CheckError": RuntimeError}
    exec(code, namespace)
    return getattr(namespace["RuntimeDash"], name)


class FakeHistory:
    def __init__(self):
        self.events = []

    def add(self, *args):
        self.events.append(args)


class ChannelTimeoutTests(unittest.TestCase):
    def test_long_configured_timeout_is_honored(self):
        method = dash_method("check_channel")
        for limit in (3, 15, 30, 60):
            for kind in ("AWG", "Sudoku"):
                with self.subTest(timeout=limit, kind=kind):
                    calls = []
                    srv = {"id": "test-entry", "name": "Тестовый вход"}
                    ch = {"key": "awg:wg0" if kind == "AWG" else "socks:1080",
                          "kind": kind, "iface": "wg0", "port": 1080,
                          "host": "203.0.113.5", "exit": "Выход"}
                    test = types.SimpleNamespace(
                        cfg=types.SimpleNamespace(settings={"channel_timeout": limit},
                                                  by_id=lambda _id: srv),
                        channels={"test-entry": [ch]}, results={}, lock=threading.Lock(),
                        hist=FakeHistory(), busy=lambda _: contextlib.nullcontext(),
                        _exit_label=lambda c: {"exit": c["exit"]},
                        note=lambda *_: None,
                        ssh=types.SimpleNamespace(run=lambda server, cmd, timeout, retry:
                            (calls.append((cmd, timeout)) or (0, "203.0.113.5\n200 0.250", ""))))
                    method(test, "test-entry", ch["key"])
                    self.assertEqual(test.results["test-entry:" + ch["key"]]["status"], "ok")
                    self.assertGreater(calls[0][1], limit)
                    self.assertIn("-m %d" % limit, calls[0][0])
                    if kind == "Sudoku":
                        self.assertIn("--socks5-hostname", calls[0][0])
                    self.assertEqual(len(test.hist.events), 1)

    def test_ipv6_from_default_site_rechecks_expected_ipv4_on_same_socks(self):
        for fallback, status, error in (
                ("203.0.113.5\n200 0.200", "ok", ""),
                ("203.0.113.6\n200 0.200", "bad", "вышел не через тот сервер"),
                ("<html>не удалось</html>\n503 0.200", "bad", "api.ipify.org — HTTP 503")):
            with self.subTest(status=status, fallback=fallback):
                result, calls = self.run_sudoku_probe(
                    [(0, "2001:db8::5\n200 0.250", ""), (0, fallback, "")])
                self.assertEqual(result["status"], status)
                self.assertIn(error, result.get("error", ""))
                self.assertEqual(len(calls), 2)
                self.assertTrue(calls[0].args[1].endswith("https://ifconfig.me"))
                self.assertTrue(calls[1].args[1].endswith("https://api.ipify.org"))
                for call in calls:
                    self.assertIn("--socks5-hostname 127.0.0.1:1080", call.args[1])

    def test_does_not_hide_wrong_ipv4_or_replace_custom_endpoint(self):
        result, calls = self.run_sudoku_probe([(0, "203.0.113.6\n200 0.250", "")])
        self.assertEqual(result["status"], "bad")
        self.assertEqual(len(calls), 1)
        result, calls = self.run_sudoku_probe([(0, "2001:db8::5\n200 0.250", "")],
                                              url="https://checker.example")
        self.assertIn("ожидался IPv4", result["error"])
        self.assertEqual(len(calls), 1)

    def test_matching_ipv6_and_expired_ipv4_budget(self):
        result, calls = self.run_sudoku_probe([(0, "2001:db8::5\n200 0.250", "")], host="2001:db8:0:0::5")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(calls), 1)
        result, calls = self.run_sudoku_probe([(0, "2001:db8::5\n200 0.250", "")], times=(0, 15))
        self.assertEqual(result["status"], "bad")
        self.assertEqual(len(calls), 1)

    def run_sudoku_probe(self, responses, *, url=None, host="203.0.113.5", times=(0, 1)):
        method = dash_method("check_channel")
        srv = {"id": "entry", "name": "Вход"}
        ch = {"key": "socks:1080", "kind": "Sudoku", "port": 1080, "host": host, "exit": "Выход"}
        run = Mock(side_effect=responses)
        panel = types.SimpleNamespace(cfg=types.SimpleNamespace(settings={"check_url": url}, by_id=lambda _: srv),
                                      channels={"entry": [ch]}, results={}, lock=threading.Lock(),
                                      hist=FakeHistory(), busy=lambda _: contextlib.nullcontext(),
                                      ssh=types.SimpleNamespace(run=run))
        with patch.object(method.__globals__["time"], "monotonic", side_effect=times):
            method(panel, "entry", ch["key"])
        self.assertEqual(len(panel.hist.events), 1)
        return panel.results["entry:socks:1080"], run.call_args_list


class SSHRetryTests(unittest.TestCase):
    def setUp(self):
        class SSHException(Exception):
            pass

        class ChannelException(SSHException):
            pass

        self.ssh_exception = SSHException
        self.channel_exception = ChannelException
        module = ast.parse((ROOT / "dash.py").read_text(encoding="utf-8"))
        names = {"CheckError", "SSHOutcomeUnknown", "SSHPool"}
        cls = [node for node in module.body if isinstance(node, ast.ClassDef) and node.name in names]
        ns = {"threading": threading, "suppress": contextlib.suppress, "read_output": read_output,
              "time": types.SimpleNamespace(sleep=lambda _: None),
              "paramiko": types.SimpleNamespace(SSHException=SSHException, ChannelException=ChannelException)}
        exec(compile(ast.Module(body=cls, type_ignores=[]), "dash.py", "exec"), ns)
        self.unknown = ns["SSHOutcomeUnknown"]
        self.check_error = ns["CheckError"]
        self.pool = ns["SSHPool"](None)
        self.transport = Mock()
        self.pool.client = Mock(return_value=types.SimpleNamespace(get_transport=lambda: self.transport))
        self.srv = {"id": "entry", "name": "Стенд"}

    def channel(self, rc, out=b"", err=b""):
        channel = Mock()
        channel.eof_received = True
        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = rc
        stdout, stderr = io.BytesIO(out), io.BytesIO(err)
        channel.recv_ready.side_effect = lambda: stdout.tell() < len(out)
        channel.recv_stderr_ready.side_effect = lambda: stderr.tell() < len(err)
        channel.recv.side_effect = stdout.read
        channel.recv_stderr.side_effect = stderr.read
        return channel

    def test_stdout_waits_for_stderr_window(self):
        channel = self.channel(7, b"stdout", b"E" * (3 * 65536))
        available = channel.recv_ready.side_effect
        channel.recv_ready.side_effect = lambda: channel.recv_stderr.call_count >= 3 and available()
        self.transport.open_session.return_value = channel
        self.assertEqual(self.pool.run(self.srv, "test streams", timeout=1),
                         (7, "stdout", "E" * (3 * 65536)))

    def test_ambiguous_mutation_is_sent_once(self):
        for fault in ("no-status", "exec-ack", "read", "send-stdin"):
            with self.subTest(fault=fault):
                channel = self.channel(-1, b"partial output" if fault == "no-status" else b"")
                if fault == "exec-ack":
                    channel.exec_command.side_effect = self.ssh_exception("channel closed")
                if fault == "read":
                    channel.recv_ready.side_effect = None
                    channel.recv_ready.return_value = True
                    channel.recv.side_effect = OSError("connection closed")
                if fault == "send-stdin":
                    channel.makefile_stdin.return_value.write.side_effect = EOFError()
                self.transport.open_session.reset_mock(return_value=True)
                self.transport.open_session.return_value = channel
                with self.assertRaisesRegex(self.unknown, "результат команды неизвестен"):
                    self.pool.run(self.srv, "test change", stdin="request")
                channel.exec_command.assert_called_once_with("test change")
                self.transport.open_session.assert_called_once()
                channel.close.assert_called_once()

    def test_read_can_repeat_and_channel_rejection_can_retry_before_dispatch(self):
        failed = self.channel(-1)
        read = self.channel(0, b"data")
        self.transport.open_session.side_effect = (failed, read)
        self.assertEqual(self.pool.run(self.srv, "test read", retry=True), (0, "data", ""))
        failed.exec_command.assert_called_once_with("test read")
        failed.close.assert_called_once()
        read.exec_command.assert_called_once_with("test read")

        rejected = self.channel_exception(1, "MaxSessions")
        mutation = self.channel(2, err=b"failed")
        self.transport.open_session.side_effect = (rejected, mutation)
        self.assertEqual(self.pool.run(self.srv, "test change", stdin="request"), (2, "", "failed"))
        mutation.exec_command.assert_called_once_with("test change")
        mutation.makefile_stdin.return_value.write.assert_called_once_with("request")
        mutation.shutdown_write.assert_called_once()

    def test_uncertain_detached_launch_is_followed_by_reading_existing_receipt(self):
        for receipt in ("0", ""):
            with self.subTest(receipt=receipt), tempfile.TemporaryDirectory() as tmp:
                panel = types.SimpleNamespace(ssh=Mock())
                panel.ssh.run.side_effect = [(0, "NEW", ""), self.unknown("итог неизвестен")] + [(0, "0\n\n%s\n" % receipt, "")] * 3
                manager = Provisioner(panel, tmp, tmp, {"CheckError": self.check_error, "SSHOutcomeUnknown": self.unknown})
                manager.put = Mock()
                job = Job(manager, "test", {})
                with patch("provision.time.sleep"):
                    if receipt:
                        self.assertEqual(manager.detached(job, self.srv, "test", "test change"), 0)
                    else:
                        with self.assertRaisesRegex(Stop, "Запуск и итог не подтверждены"):
                            manager.detached(job, self.srv, "test", "test change")
                launches = [c for c in panel.ssh.run.call_args_list if "nohup setsid" in c.args[1]]
                self.assertEqual(len(launches), 1)
                self.assertFalse(launches[0].kwargs["retry"])
                self.assertTrue(panel.ssh.run.call_args.kwargs["retry"])


class FirewallConfirmationTests(unittest.TestCase):
    def run_panel(self, confirmation):
        method = dash_method("fw_enable")
        srv = {"id": "test-entry", "name": "Тестовый вход", "port": 22}
        recorded = []
        job = types.SimpleNamespace()
        fake = types.SimpleNamespace(
            cfg=types.SimpleNamespace(by_id=lambda _: srv),
            fw={}, fwjob={}, busy=lambda _: contextlib.nullcontext(),
            check_fw=lambda sid: None,
            _fw_channels=lambda sid: [],
            _fw_probe=lambda _srv, _ch: (True, {}, {}),
            _fw_run=lambda _srv, payload, timeout=120:
                (recorded.append(payload["do"]) or
                 ({"ok": True, "active": True} if payload["do"] == "enable" else confirmation)),
            note=lambda *args: recorded.append(args),
        )
        fake.check_fw = lambda sid: fake.fw.__setitem__(sid, {
            "ok": True, "plan": {"state": "off", "cmds": ["ufw allow 22/tcp"]}})
        method(fake, "test-entry")
        self.assertIn("confirm", recorded)
        return fake.fwjob["test-entry"]

    def test_panel_refuses_inactive_ufw_after_confirm(self):
        result = self.run_panel({"ok": True, "active": False})
        self.assertIs(result["ok"], False)
        self.assertTrue(result["done"])

    def test_panel_refuses_failed_confirmation(self):
        result = self.run_panel({"ok": False, "active": True})
        self.assertIs(result["ok"], False)

    def test_panel_accepts_confirmed_active_ufw(self):
        result = self.run_panel({"ok": True, "active": True})
        self.assertIs(result["ok"], True)

    def test_server_confirm_never_reports_success_for_disabled_ufw(self):
        for is_on in (False, True):
            with self.subTest(ufw_active=is_on):
                code = fw.FW_PY.replace(
                    'if P["do"] == "confirm":',
                    'def sh(c, t=600):\n    return (0, "Status: %s\\n")\n'
                    'if P["do"] == "confirm":' % ("active" if is_on else "inactive"), 1)
                code = code.replace('UNDO = "/root/.vpn-dash-fw-undo"',
                                    'UNDO = "/tmp/vpn-dash-regression-undo-does-not-exist"')
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    with self.assertRaises(SystemExit):
                        exec('P = {"do": "confirm"}\n' + code, {"__name__": "__runtime_test__"})
                answer = json.loads(buf.getvalue().strip().splitlines()[-1])
                self.assertEqual(answer["active"], is_on)
                self.assertEqual(answer["ok"], is_on)


class GovblockConfirmationTests(unittest.TestCase):
    def test_server_keeps_rollback_until_rules_and_boot_are_confirmed(self):
        for failure in (None, "chain", "reload", "enable", "boot", "expired"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                undo = Path(tmp) / ".vpn-dash-gov-undo"
                rollback = undo.with_suffix(".sh")
                previous = Path(tmp) / "govblock.nft.prev"
                if failure != "expired":
                    rollback.touch()
                    previous.touch()
                meta = {"sha": "current", "at": 1000}
                saved = {"sha": "previous", "at": 999} if failure == "expired" else meta
                (Path(tmp) / "govblock.json").write_text(json.dumps(saved), encoding="utf-8")
                code = govblock.GOV_PY.replace('D = "/etc/vpn-dash"', "D = %r" % tmp)
                code = code.replace('/root/.vpn-dash-gov-undo', undo.as_posix())

                def command(cmd, **kwargs):
                    if cmd.startswith("nft list table"):
                        # Таблица существует даже в сценарии с удалённой цепочкой input.
                        return subprocess.CompletedProcess(cmd, 0, "")
                    if cmd.startswith("nft list chain"):
                        return subprocess.CompletedProcess(cmd, int(failure == "chain"), "")
                    if cmd.startswith("systemctl is-enabled"):
                        state = "enabled-runtime" if failure == "boot" else "enabled"
                        return subprocess.CompletedProcess(cmd, 0, state + "\n")
                    failed = ((failure == "reload" and "daemon-reload" in cmd)
                              or (failure == "enable" and " enable " in cmd))
                    return subprocess.CompletedProcess(cmd, int(failed), "сбой systemd" if failed else "")

                buf = io.StringIO()
                with patch("subprocess.run", side_effect=command), contextlib.redirect_stdout(buf):
                    with self.assertRaises(SystemExit):
                        exec(code, {"P": {"do": "confirm", "meta": meta}})
                answer = json.loads(buf.getvalue())
                self.assertIs(answer["ok"], failure is None)
                pending = failure not in (None, "expired")
                self.assertEqual(rollback.exists(), pending)
                self.assertEqual(previous.exists(), pending)
                if failure is not None:
                    self.assertIs(answer["undo_pending"], pending)

    def test_panel_uses_server_confirmation_even_if_connectivity_is_unchanged(self):
        apply = dash_method("gov_apply")
        srv = {"id": "entry", "name": "Тестовый вход"}
        for confirmation in ({"ok": True, "on": True, "boot": True},
                             {"ok": True, "on": False, "boot": True},
                             {"ok": True, "on": True, "boot": False},
                             {"ok": False, "undo_pending": True, "msg": "служба не включена"},
                             {"ok": False, "undo_pending": False, "msg": "применение списка не подтверждено"}):
            with self.subTest(confirmation=confirmation):
                responses = {"who": {}, "apply": {"ok": True}, "confirm": confirmation}
                calls = []
                fake = types.SimpleNamespace(
                    cfg=types.SimpleNamespace(by_id=lambda _: srv, settings={}), govjob={}, status={},
                    gov={"at": 1000, "v4": ["203.0.113.0/24"], "v6": [], "sha": "test"},
                    busy=lambda _: contextlib.nullcontext(), note=lambda *_: None,
                    _fw_channels=lambda _: [], _fw_probe=lambda *_: (True, {}, {}),
                    _gov_run=lambda server, payload, timeout=120: calls.append(payload) or responses[payload["do"]],
                    check_server=lambda _: None,
                )
                expected = confirmation["ok"] and confirmation["on"] and confirmation["boot"]
                self.assertIs(apply(fake, srv["id"]), expected)
                self.assertEqual([payload["do"] for payload in calls], ["who", "apply", "confirm"])
                self.assertEqual(calls[-1]["meta"], calls[-2]["meta"])
                job = fake.govjob[srv["id"]]
                self.assertIs(job["ok"], expected)
                self.assertTrue(job["done"])
                self.assertEqual(job["undo_at"], None if expected or confirmation.get("undo_pending") is False else 1300)


class TopologyConfirmationTests(unittest.TestCase):
    def make_provisioner(self, tmp):
        entry = {"id": "entry", "name": "Тестовый вход", "role": "entry"}
        exit_ = {"id": "exit", "name": "Тестовый выход", "host": "192.0.2.10"}
        servers = {s["id"]: s for s in (entry, exit_)}
        panel = types.SimpleNamespace(
            cfg=types.SimpleNamespace(by_id=servers.get, get_pw=lambda _: "test"),
            channels={}, results={}, running=set(), note=lambda *_: None,
            ssh=types.SimpleNamespace(drop=lambda _: None),
            check_channel=lambda *_: None, check_server=lambda _: None,
        )
        provisioner = Provisioner(panel, tmp, tmp, {})
        provisioner.link_plan = lambda *_: {"ok": True, "cross": False, "name": "Test"}
        provisioner.put = lambda *args: None
        provisioner.detached = lambda *args, **kwargs: 0
        return provisioner

    def test_link_reports_final_outcome_of_required_checks(self):
        cases = (
            ("awg", "ok", "ok", ()),
            ("awg", "warn", "ok", ()),
            ("awg", "bad", "ok", ("новый путь не прошёл проверку",)),
            ("awg", None, "ok", ("новый путь не прошёл проверку",)),
            ("sudoku", "ok", "bad", ("перестали работать прежние каналы",)),
            ("sudoku", "bad", "bad", ("новый путь не прошёл проверку", "перестали работать прежние каналы")),
            ("vless", "ok", "warn", ()),
            ("vless", "bad", "ok", ("новый путь не прошёл проверку",)),
        )
        for proto, new, old, errors in cases:
            with self.subTest(proto=proto, new=new, old=old), tempfile.TemporaryDirectory() as tmp:
                manager = self.make_provisioner(tmp)
                panel = manager.d
                before = {"key": "awg:old", "kind": "AWG", "exit_id": "other"}
                after = {"key": "new", "kind": manager.LINK_KIND[proto], "exit_id": "exit"}
                panel.channels["entry"] = [before]
                panel.results["entry:awg:old"] = {"status": "ok"}

                def check_all(_):
                    panel.results["entry:awg:old"] = {"status": old}
                    if new is not None:
                        panel.channels["entry"].append(after)
                        panel.results["entry:new"] = {"status": new}

                panel.check_all = check_all
                panel.proto_test = lambda _: {"tests": {"VLESS-Test": {"ok": new == "ok"}}}
                response = '{"port": 1935}' if proto == "vless" else "51820\n"
                manager.sh = lambda *args, **kwargs: (0, response, "")
                with patch("provision.threading.Thread", side_effect=self.run_inline):
                    jid = manager.start_link("entry", "exit", proto)
                job = manager.get(jid)
                expected = "error" if errors else "ok"
                self.assertEqual(job["status"], expected)
                step = next(s for s in job["steps"] if s["key"] == "panel")
                self.assertEqual(step["status"], expected)
                for error in errors:
                    self.assertIn(error, job["error"])
                if errors:
                    self.assertIn("Настройки связи уже применены", job["error"])

    def test_reorder_and_unlink_fail_when_a_retained_channel_stops_working(self):
        cases = (("ok", "warn", "ok"), ("ok", "bad", "error"),
                 ("warn", None, "error"), ("bad", "bad", "ok"))
        for operation in ("reorder", "unlink"):
            for before, after, expected in cases:
                with self.subTest(operation=operation, before=before, after=after), tempfile.TemporaryDirectory() as tmp:
                    manager = self.make_provisioner(tmp)
                    panel = manager.d
                    panel.channels["entry"] = [
                        {"key": "keep", "kind": "AWG", "exit_id": "other", "tag": "AWG-Keep", "n": 1},
                        {"key": "target", "kind": "AWG", "exit_id": "exit", "tag": "AWG-Target", "n": 2},
                    ]
                    panel.results.update({"entry:keep": {"status": before}, "entry:target": {"status": "ok"}})

                    def check_all(_):
                        panel.results.pop("entry:keep")
                        if after is not None:
                            panel.results["entry:keep"] = {"status": after}
                        if operation == "unlink":
                            panel.channels["entry"].pop()
                            panel.results.pop("entry:target")

                    panel.check_all = check_all
                    with patch("provision.threading.Thread", side_effect=self.run_inline):
                        if operation == "unlink":
                            jid = manager.start_unlink("entry", "exit", "awg")
                        else:
                            jid = manager.start_reorder("entry", ["AWG-Target", "AWG-Keep"])
                    job = manager.get(jid)
                    steps = {s["key"]: s["status"] for s in job["steps"]}
                    self.assertEqual(job["status"], expected)
                    self.assertEqual(steps["entry"], "ok")
                    self.assertEqual(steps["panel"], expected)
                    if operation == "unlink":
                        self.assertEqual(steps["exit"], "warn")  # отдельное предупреждение об оставшемся клиенте
                    if expected == "error":
                        self.assertIn("перестали работать прежние каналы (1)", job["error"])
                        applied = ("Путь уже удалён со входа" if operation == "unlink" else "Новый порядок цепочки уже применён")
                        self.assertIn(applied, job["error"])

    def test_optional_optimization_warning_preserves_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_provisioner(tmp)
            manager.sh = lambda *args, **kwargs: (0, "0\nUbuntu", "")
            manager.detached = lambda *args, **kwargs: 1
            job = Job(manager, "install", {})
            job.plan([("ssh", "SSH", ""), ("opt", "Оптимизация", "")])
            srv = manager.d.cfg.by_id("exit")
            with patch("provision.threading.Thread", side_effect=self.run_inline):
                manager._spawn(job, lambda j, _: manager._prepare(j, srv, {"opt": True, "upd": False}), None)
            self.assertEqual(job.steps[-1]["status"], "warn")
            self.assertEqual(job.status, "ok")

    def test_backup_requires_a_working_chain_link_on_each_entry(self):
        for mode in ("healthy", "duplicate", "outside-chain", "stale", "old-broken"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                manager = self.make_provisioner(tmp)
                panel = manager.d
                entry, exit_ = (panel.cfg.by_id(sid) for sid in ("entry", "exit"))
                entry["group"] = exit_["group"] = "group"
                exit_.update(role="exit", name="Test")
                other = {"id": "other", "name": "Второй вход", "role": "entry", "group": "group"}
                panel.cfg.servers = [entry, other, exit_]
                panel.channels["entry"] = [{"key": "old", "kind": "AWG"}]
                panel.results["entry:old"] = {"status": "ok"}
                manager.sh = lambda *args, **kwargs: (0, "52345\n", "")

                def check_all(_):
                    link = {"key": "new", "exit_id": "exit", "kind": "Sudoku", "tag": "Sudoku-Test", "n": 2}
                    for sid in ("entry", "other"):
                        panel.channels.setdefault(sid, []).append(dict(link))
                        panel.results[sid + ":new"] = {"status": "warn", "at": time.time()}
                    if mode == "duplicate":
                        panel.channels["entry"].append(dict(link))
                        panel.channels["other"].clear()
                    elif mode == "outside-chain":
                        panel.channels["other"][0]["n"] = None
                    elif mode == "stale":
                        panel.results["other:new"]["at"] = 1
                    panel.results["entry:old"] = {"status": "bad" if mode == "old-broken" else "ok", "at": time.time()}

                panel.check_all = check_all
                with patch("provision.threading.Thread", side_effect=self.run_inline):
                    job = manager.get(manager.start_sudoku_backup(exit_))
                expected = "ok" if mode == "healthy" else "error"
                self.assertEqual(job["status"], expected)
                self.assertEqual(job["steps"][-1]["status"], expected)
                if mode in ("duplicate", "outside-chain", "stale"):
                    self.assertIn("Второй вход", job["error"])
                if mode == "old-broken":
                    self.assertIn("перестали работать прежние каналы", job["error"])

    def test_migration_preserves_docker_until_the_expected_tunnel_is_verified(self):
        for mode in ("healthy", "cleanup-warning", "absent", "old-port", "stale", "unreachable", "after-removal"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                manager = self.make_provisioner(tmp)
                panel = manager.d
                entry, exit_ = (panel.cfg.by_id(sid) for sid in ("entry", "exit"))
                exit_["role"] = "exit"
                panel.cfg.servers = [entry, exit_]
                panel.status = {"exit": {"data": {"exit": {"awg": {"mode": "docker"}}}}}
                channel = {"key": "awg:wg0", "kind": "AWG", "exit_id": "exit", "iface": "wg0", "tag": "AWG-Test"}
                panel.channels["entry"] = [channel]
                checks, deletes = [], []

                def check_all(_):
                    checks.append(True)
                    panel.status["entry"] = {"ok": True, "at": time.time(), "data": {"entry": {"awg": [
                        {"iface": "wg0", "endpoint": exit_["host"] + (":42424" if mode == "old-port" else ":51820")},
                    ]}}}
                    if mode == "absent":
                        panel.channels["entry"].clear()
                    broken = mode == "unreachable" or (mode == "after-removal" and len(checks) > 1)
                    panel.results["entry:awg:wg0"] = {
                        "at": 1 if mode == "stale" else time.time(), "status": "bad" if broken else "warn",
                    }

                def sh(_srv, cmd, **kwargs):
                    if cmd.startswith("docker rm"):
                        deletes.append(bool(checks))
                        return (1, "сбой удаления", "") if mode == "cleanup-warning" else (0, "REMOVED\n", "")
                    return 0, "51820\n", ""

                panel.check_all = check_all
                manager.sh = sh
                with patch("provision.threading.Thread", side_effect=self.run_inline):
                    job = manager.get(manager.start_migrate(exit_, "10.9.0"))
                success = mode in ("healthy", "cleanup-warning")
                verified = success or mode == "after-removal"
                self.assertEqual(deletes, [True] if verified else [])
                self.assertEqual(len(checks), 2 if verified else 1)
                self.assertEqual(job["status"], "ok" if success else "error")
                steps = {s["key"]: s["status"] for s in job["steps"]}
                self.assertEqual(steps["verify"], "ok" if verified else "error")
                self.assertEqual(steps["panel"], ("ok" if success else "error") if verified else "skip")
                self.assertEqual(steps["docker"], "warn" if mode == "cleanup-warning" else "ok" if verified else "skip")
                self.assertEqual(job["result"]["post"][0]["n"], 1)
                if mode == "after-removal":
                    self.assertIn("Контейнер уже удалён", job["error"])

    @staticmethod
    def run_inline(*, target, daemon):
        return types.SimpleNamespace(start=target)


if __name__ == "__main__":
    unittest.main()

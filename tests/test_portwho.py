#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for portwho. All fixture based - no live sockets, no admin needed.

    python -m pytest tests/ -q
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portwho  # noqa: E402


# Real `netstat -ano` on a zh-CN Windows 10 box, trimmed. Two leading spaces,
# CJK header that must be skipped, IPv4 and IPv6 rows.
NETSTAT_WIN = """\ufeff

活动连接

  协议  本地地址          外部地址        状态           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1680
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:8082         0.0.0.0:0              LISTENING       13784
  TCP    192.168.10.18:52341    203.0.113.10:443       ESTABLISHED     9012
  TCP    [::]:135               [::]:0                 LISTENING       1680
  TCP    [::1]:5432             [::]:0                 LISTENING       20100
  UDP    0.0.0.0:500            *:*                                    4596
  UDP    127.0.0.1:1900         *:*                                    13700
  UDP    [::]:3702              *:*                                    13520
"""

NETSTAT_LINUX = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1043/postgres
tcp6       0      0 :::80                   :::*                    LISTEN      2011/nginx
udp        0      0 0.0.0.0:68              0.0.0.0:*                           900/dhclient
"""

TASKLIST_WIN = """"System Idle Process","0","Services","0","8 K"
"System","4","Services","0","18,064 K"
"svchost.exe","1680","Services","0","12,348 K"
"QQ.exe","13784","Console","1","201,776 K"
"postgres.exe","20100","Services","0","44,112 K"
"""

LSOF_MAC = """p812
csshd
n*:22
p2011
cnginx
n[::1]:8080
p900
cdhclient
n192.168.1.5:68
"""


class TestSplitHostPort(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(portwho.split_hostport("127.0.0.1:8080"), ("127.0.0.1", 8080))

    def test_wildcard(self):
        self.assertEqual(portwho.split_hostport("0.0.0.0:135"), ("0.0.0.0", 135))

    def test_ipv6_bracketed(self):
        self.assertEqual(portwho.split_hostport("[::]:135"), ("::", 135))

    def test_ipv6_loopback(self):
        self.assertEqual(portwho.split_hostport("[::1]:5432"), ("::1", 5432))

    def test_star(self):
        self.assertEqual(portwho.split_hostport("*:*"), ("*", None))

    def test_dotted_legacy(self):
        # Windows 2003 style
        self.assertEqual(portwho.split_hostport("127.0.0.1.5000"), ("127.0.0.1", 5000))

    def test_empty(self):
        self.assertEqual(portwho.split_hostport(""), ("", None))

    def test_garbage(self):
        self.assertEqual(portwho.split_hostport("hello"), ("hello", None))


class TestParseNetstatWindows(unittest.TestCase):
    def setUp(self):
        self.records = portwho.parse_netstat(NETSTAT_WIN)

    def test_skips_header(self):
        # 6 TCP (2 of them IPv6) + 3 UDP = 9 rows; CJK header lines dropped
        self.assertEqual(len(self.records), 9)
        self.assertFalse(any("协议" in x.host for x in self.records))

    def test_tcp_listen(self):
        r = [x for x in self.records if x.port == 445][0]
        self.assertEqual(r.proto, "tcp")
        self.assertEqual(r.host, "0.0.0.0")
        self.assertEqual(r.state, "LISTENING")
        self.assertEqual(r.pid, 4)

    def test_established_has_remote(self):
        r = [x for x in self.records if x.port == 52341][0]
        self.assertEqual(r.state, "ESTABLISHED")
        self.assertEqual(r.pid, 9012)
        self.assertFalse(r.is_listen())

    def test_ipv6(self):
        r = [x for x in self.records if x.port == 5432][0]
        self.assertEqual(r.host, "::1")
        self.assertEqual(r.pid, 20100)
        self.assertEqual(r.local_addr(), "[::1]:5432")

    def test_udp_has_no_state(self):
        r = [x for x in self.records if x.port == 500][0]
        self.assertEqual(r.proto, "udp")
        self.assertEqual(r.state, "")
        self.assertTrue(r.is_listen())

    def test_bom_does_not_break_first_row(self):
        # the BOM sits on the blank line before the header; nothing should leak in
        self.assertFalse(any("\ufeff" in x.host for x in self.records))


class TestParseNetstatLinux(unittest.TestCase):
    def setUp(self):
        self.records = portwho.parse_netstat(NETSTAT_LINUX)

    def test_count(self):
        self.assertEqual(len(self.records), 4)

    def test_sshd(self):
        r = [x for x in self.records if x.port == 22][0]
        self.assertEqual(r.pid, 812)
        self.assertEqual(r.state, "LISTENING")

    def test_tcp6(self):
        r = [x for x in self.records if x.port == 80][0]
        self.assertEqual(r.proto, "tcp6")
        self.assertEqual(r.host, "::")

    def test_udp(self):
        r = [x for x in self.records if x.port == 68][0]
        self.assertEqual(r.proto, "udp")
        self.assertEqual(r.pid, 900)


class TestParseTasklist(unittest.TestCase):
    def test_csv_with_comma_in_memory(self):
        procs = portwho.parse_tasklist(TASKLIST_WIN)
        self.assertEqual(procs[13784], "QQ.exe")
        self.assertEqual(procs[4], "System")
        self.assertEqual(procs[20100], "postgres.exe")

    def test_pid_zero_is_kept_out(self):
        # System Idle Process has pid 0; keeping it would be misleading
        procs = portwho.parse_tasklist(TASKLIST_WIN)
        self.assertNotIn(0, procs)

    def test_header_row_skipped(self):
        procs = portwho.parse_tasklist('"Image Name","PID","Session Name","Session#","Mem Usage"\n')
        self.assertEqual(procs, {})


class TestParseLsof(unittest.TestCase):
    def test_fields(self):
        recs = portwho.parse_lsof(LSOF_MAC)
        self.assertEqual(len(recs), 3)
        by_port = {r.port: r for r in recs}
        self.assertEqual(by_port[22].pid, 812)
        self.assertEqual(by_port[8080].host, "::1")


class TestSelect(unittest.TestCase):
    def setUp(self):
        self.records = portwho.parse_netstat(NETSTAT_WIN)

    def test_by_port(self):
        hits = portwho.select(self.records, port=135)
        self.assertEqual(len(hits), 2)          # IPv4 + IPv6
        self.assertTrue(all(h.port == 135 for h in hits))

    def test_listening_only_excludes_established(self):
        hits = portwho.select(self.records, port=52341)
        self.assertEqual(hits, [])

    def test_include_all(self):
        hits = portwho.select(self.records, port=52341, listening_only=False)
        self.assertEqual(len(hits), 1)

    def test_proto_filter(self):
        hits = portwho.select(self.records, port=1900, proto="udp")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].proto, "udp")

    def test_list_mode_sorted(self):
        hits = portwho.select(self.records)
        # listening TCP first (port ascending), then UDP (no state) ascending
        self.assertEqual([h.port for h in hits], [135, 135, 445, 5432, 8082, 500, 1900, 3702])
        self.assertTrue(all(h.state in ("LISTENING", "") for h in hits))

    def test_dedup_by_local_socket(self):
        # two established rows differing only in peer = one server, one row out
        recs = portwho.parse_netstat(
            "  TCP    127.0.0.1:9790   127.0.0.1:51000   ESTABLISHED   30856\n"
            "  TCP    127.0.0.1:9790   127.0.0.1:51001   ESTABLISHED   30856\n")
        hits = portwho.select(recs, port=9790, listening_only=False)
        self.assertEqual(len(hits), 1)

    def test_all_drops_time_wait_noise(self):
        recs = portwho.parse_netstat(
            "  TCP    127.0.0.1:9790   0.0.0.0:0       LISTENING     30856\n"
            "  TCP    127.0.0.1:9790   127.0.0.1:51000  TIME_WAIT     0\n"
            "  TCP    127.0.0.1:9790   127.0.0.1:51001  TIME_WAIT     0\n")
        hits = portwho.select(recs, port=9790, listening_only=False)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].state, "LISTENING")


class TestProcNetHex(unittest.TestCase):
    def test_ipv4_little_endian(self):
        # 0100007F -> 127.0.0.1
        self.assertEqual(portwho._hex_ip("0100007F", False), "127.0.0.1")

    def test_ipv4_wildcard(self):
        self.assertEqual(portwho._hex_ip("00000000", False), "0.0.0.0")

    def test_ipv6_loopback(self):
        # /proc/net/tcp6 stores ::1 as 00000000000000000000000001000000
        out = portwho._hex_ip("00000000000000000000000001000000", True)
        self.assertEqual(out, "::1")

    def test_bad_hex_passthrough(self):
        self.assertEqual(portwho._hex_ip("ZZZZ", False), "ZZZZ")


class TestReverseLookup(unittest.TestCase):
    """--process filters rows by name after the pid map is built."""

    def test_substring_case_insensitive(self):
        rows = [
            {"proto": "tcp", "local": "0.0.0.0:80", "state": "LISTENING",
             "pid": 1, "process": "nginx.exe", "exe": "C:/nginx/nginx.exe"},
            {"proto": "tcp", "local": "0.0.0.0:81", "state": "LISTENING",
             "pid": 2, "process": "svchost.exe", "exe": ""},
        ]
        needle = "NGINX"
        hit = [d for d in rows if needle.lower() in (d["process"] or "").lower()]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["pid"], 1)

    def test_matches_exe_path_too(self):
        rows = [{"proto": "tcp", "local": "0.0.0.0:80", "state": "LISTENING",
                 "pid": 1, "process": "", "exe": "C:/tools/redis-server.exe"}]
        needle = "redis"
        hit = [d for d in rows
               if needle in (d["process"] or "").lower() or needle in (d["exe"] or "").lower()]
        self.assertEqual(len(hit), 1)


class TestCli(unittest.TestCase):
    def test_port_out_of_range(self):
        self.assertEqual(portwho.main(["70000"]), 2)

    def test_no_args_prints_help(self):
        self.assertEqual(portwho.main([]), 2)


class TestWinKillStrategy(unittest.TestCase):
    """The escalation logic, without touching a real process."""

    def _patch(self, results):
        """results: list of (rc, out, err) the fake taskkill returns in order."""
        calls = []
        seq = list(results)

        def fake_run(cmd, capture_output=True, timeout=20):
            calls.append(list(cmd))

            class R:
                pass
            r = R()
            rc, out, err = seq.pop(0)
            r.returncode = rc
            r.stdout = out.encode("mbcs", "replace")
            r.stderr = err.encode("mbcs", "replace")
            return r
        return fake_run, calls

    def test_graceful_success_no_escalation(self):
        fake, calls = self._patch([(0, "", "")])
        orig = portwho.subprocess.run
        portwho.subprocess.run = fake
        try:
            ok, err = portwho._win_kill(4242, force=False)
        finally:
            portwho.subprocess.run = orig
        self.assertTrue(ok)
        self.assertEqual(calls, [["taskkill", "/PID", "4242"]])

    def test_escalates_to_force(self):
        # graceful fails the way Windows reports a console-less process
        fake, calls = self._patch([(1, "", "只能强行终止这个进程"), (0, "成功", "")])
        orig = portwho.subprocess.run
        portwho.subprocess.run = fake
        try:
            ok, err = portwho._win_kill(4242, force=False)
        finally:
            portwho.subprocess.run = orig
        self.assertTrue(ok)
        self.assertEqual(calls[1], ["taskkill", "/PID", "4242", "/F"])

    def test_force_only_one_attempt(self):
        fake, calls = self._patch([(1, "", "拒绝访问")])
        orig = portwho.subprocess.run
        portwho.subprocess.run = fake
        try:
            ok, err = portwho._win_kill(4242, force=True)
        finally:
            portwho.subprocess.run = orig
        self.assertFalse(ok)
        self.assertEqual(len(calls), 1)
        self.assertIn("拒绝访问", err)

    def test_both_fail_reports_last_error(self):
        fake, calls = self._patch([(1, "", "第一次失败"), (1, "", "第二次失败")])
        orig = portwho.subprocess.run
        portwho.subprocess.run = fake
        try:
            ok, err = portwho._win_kill(4242, force=False)
        finally:
            portwho.subprocess.run = orig
        self.assertFalse(ok)
        self.assertIn("第二次失败", err)


class TestFmtTable(unittest.TestCase):
    def test_peer_column_only_when_real_peer(self):
        out = portwho._fmt_table([
            {"proto": "tcp", "local": "0.0.0.0:80", "state": "LISTENING",
             "pid": 1, "process": "nginx", "peer": "0.0.0.0:0"}])
        self.assertNotIn("PEER", out)

    def test_peer_column_appears_for_established(self):
        out = portwho._fmt_table([
            {"proto": "tcp", "local": "127.0.0.1:9790", "state": "ESTABLISHED",
             "pid": 1, "process": "x", "peer": "127.0.0.1:50965"}])
        self.assertIn("PEER", out)
        self.assertIn("127.0.0.1:50965", out)

    def test_empty(self):
        self.assertEqual(portwho._fmt_table([]), "no matching socket")

    def test_unknown_pid_shows_dash(self):
        out = portwho._fmt_table([
            {"proto": "tcp", "local": "0.0.0.0:80", "state": "LISTENING",
             "pid": 0, "process": "", "peer": ""}])
        self.assertIn(" ?", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)

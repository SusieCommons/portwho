#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""portwho - tell me which process is holding a port.

Single file, zero dependencies, Windows / Linux / macOS.

    portwho 8080            # who owns 8080
    portwho --list          # everything listening
    portwho --list --all    # include established / udp
    portwho 8080 --json     # machine readable
    portwho 8080 --kill     # terminate the owner (asks first)

Exit codes: 0 = found, 1 = nothing matched, 2 = error.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import platform
import re
import signal
import subprocess
import sys

IS_WIN = os.name == "nt"
IS_MAC = platform.system() == "Darwin"

# netstat prints the state column in the system locale on some builds.
# Anything that is not one of these is treated as a state we do not care about.
LISTEN_STATES = {"LISTENING", "LISTEN", "ESTABLISHED", "SYN_SENT", "TIME_WAIT",
                 "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"}

# Sockets in these states have no owning pid and no live process. Listing them
# adds nothing but noise.
DEAD_STATES = {"TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
               "LAST_ACK", "CLOSING", "CLOSED"}


def _wildcard_peer(remote):
    """True when the foreign address is the any-address wildcard.

    Windows: `0.0.0.0:0`, `[::]:0`, `*:*`
    Linux:   `0.0.0.0:*`, `[::]:*`, `:::0`
    """
    if not remote:
        return True
    r = remote.strip()
    if r in ("*:*", "*"):
        return True
    host, port = split_hostport(r)
    if port not in (0, None):
        return False
    return host in ("0.0.0.0", "::", "*", "")


class Record:
    """One row of netstat / lsof output."""

    __slots__ = ("proto", "host", "port", "state", "pid", "remote")

    def __init__(self, proto, host, port, state, pid, remote=""):
        self.proto = proto        # tcp / tcp6 / udp / udp6
        self.host = host          # 0.0.0.0 / :: / 127.0.0.1
        self.port = port          # int
        self.state = state        # LISTENING / ESTABLISHED / ""
        self.pid = pid            # int, 0 = unknown
        self.remote = remote

    def is_listen(self):
        # UDP has no listen state; a bound UDP socket shows an empty state.
        # A listening TCP row still has a "foreign" column, but it is the
        # wildcard 0.0.0.0:0 / [::]:0 / *:* - that is not a real peer.
        return self.state in ("LISTENING", "") and _wildcard_peer(self.remote)

    def local_addr(self):
        # IPv6 literal needs brackets, otherwise "::1:8080" is ambiguous.
        if ":" in self.host:
            return "[%s]:%d" % (self.host, self.port)
        return "%s:%d" % (self.host, self.port)

    def as_dict(self, name="", exe=""):
        return {
            "proto": self.proto,
            "local": self.local_addr(),
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "pid": self.pid,
            "process": name,
            "exe": exe,
            "peer": self.remote or "",
        }

    def __repr__(self):
        return "<Record %s %s:%d %s pid=%d>" % (
            self.proto, self.host, self.port, self.state, self.pid)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def split_hostport(token):
    """`0.0.0.0:135` / `[::]:135` / `*:*` / `127.0.0.1.5000` -> (host, port|None).

    Windows prints IPv4 as a.b.c.d:port and IPv6 as [::]:port. Older builds
    print IPv4 as 1.2.3.4.5000 with a dot, so that is handled too.
    """
    if not token:
        return "", None
    token = token.strip()
    if token.startswith("["):
        end = token.find("]")
        if end < 0:
            return token, None
        host = token[1:end]
        rest = token[end + 1:]
        port = rest.lstrip(":") if rest.startswith(":") else ""
        return host, _int(port)
    if token.count(":") == 1:
        host, _, port = token.partition(":")
        return host, _int(port)
    if token.count(":") > 1:                 # bare IPv6 without brackets
        host, _, port = token.rpartition(":")
        return host, _int(port)
    # dotted form: last segment after the final dot, only if it looks numeric
    head, _, tail = token.rpartition(".")
    if head and tail.isdigit():
        return head, int(tail)
    return token, _int(token)


def _int(s):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return None


def _norm_state(s):
    """Linux prints LISTEN, Windows prints LISTENING. Normalise to one word."""
    s = (s or "").upper()
    if s in ("LISTEN", "LISTENING"):
        return "LISTENING"
    return s


def parse_netstat(text):
    """Parse `netstat -ano` (Windows) or `netstat -tunap` (Linux/macOS) output.

    The two dialects differ enough that guessing from column count alone is
    unreliable, so the shape is detected once per line:

      Windows  tcp  0.0.0.0:135   0.0.0.0:0      LISTENING   1680
      Linux    tcp  0  0 0.0.0.0:22  0.0.0.0:*   LISTEN      812/sshd
      macOS    tcp4 0  0 *.22       *.*          LISTEN
    """
    out = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line:
            continue
        parts = line.split()
        head = parts[0].lower()
        if not (head.startswith("tcp") or head.startswith("udp")):
            continue
        proto = head
        is_udp = head.startswith("udp")

        # Linux/macOS put Recv-Q / Send-Q in columns 1 and 2; Windows does not.
        posix = len(parts) > 2 and parts[1].isdigit() and parts[2].isdigit()
        try:
            if posix:
                local = parts[3]
                foreign = parts[4] if len(parts) > 4 else ""
                if is_udp:
                    # udp has no state column: pid/prog sits right after foreign
                    state, pid_idx = "", 5
                else:
                    state, pid_idx = (parts[5] if len(parts) > 5 else ""), 6
            else:
                local = parts[1]
                foreign = parts[2] if len(parts) > 2 else ""
                if is_udp:
                    # Windows udp rows: proto local foreign pid
                    state, pid_idx = "", 3
                else:
                    state, pid_idx = (parts[3] if len(parts) > 3 else ""), 4
            pid = 0
            if len(parts) > pid_idx:
                pid = _int(parts[pid_idx].split("/")[0]) or 0
        except IndexError:
            continue

        host, port = split_hostport(local)
        if port is None:
            continue
        out.append(Record(proto, host, port, _norm_state(state), pid or 0, foreign))
    return out


def parse_tasklist(text):
    """Parse `tasklist /FO CSV /NH`. Returns {pid: process name}.

    A quoted CSV row looks like:
        "smss.exe","864","Services","0","1,096 K"
    The memory column contains a comma, so a plain split() loses the columns -
    that is the whole reason this uses the csv module.
    """
    procs = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3:
            continue
        name, pid = row[0], _int(row[1])
        if name.lower() in ("image name", "映像名称", "进程名"):
            continue
        if pid:
            procs[pid] = name
    return procs


def parse_lsof(text):
    """Parse `lsof -nP -iTCP -sTCP:LISTEN -Fpcn` field output (macOS/Linux).

    Field mode emits one attribute per line: p<pid>, c<command>, n<addr>.
    Records are separated by a new `p` line.
    """
    out = []
    pid, cmd, proto = 0, "", "tcp"
    for line in text.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            pid = _int(val) or 0
        elif tag == "c":
            cmd = val
        elif tag == "n":
            # n*:8080 or n127.0.0.1:8080 or n[::1]:8080->[::1]:5000
            addr = val.split("->")[0]
            host, port = split_hostport(addr)
            if port:
                out.append(Record(proto, host, port, "LISTENING", pid))
        elif tag == "P":
            proto = val.lower()
    return out


# --------------------------------------------------------------------------
# process lookup
# --------------------------------------------------------------------------

def _win_exe_path(pid):
    """QueryFullProcessImageNameW - works for processes we cannot open fully.

    PROCESS_QUERY_LIMITED_INFORMATION (0x1000) is enough for the path and does
    not need SeDebugPrivilege for same-user processes.
    """
    if not IS_WIN or not pid:
        return ""
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD)]
        k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]

        h = k32.OpenProcess(0x1000, False, pid)
        if not h:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(32768)
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
            return ""
        finally:
            k32.CloseHandle(h)
    except Exception:
        return ""


def _proc_name(pid):
    """Best-effort process name for a pid, cross platform."""
    if not pid:
        return ""
    if IS_WIN:
        exe = _win_exe_path(pid)
        return os.path.basename(exe) if exe else ""
    try:
        with open("/proc/%d/comm" % pid, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        pass
    try:
        r = subprocess.run(["ps", "-p", str(pid), "-o", "comm="],
                           capture_output=True, text=True, timeout=5)
        return os.path.basename(r.stdout.strip())
    except Exception:
        return ""


def _all_procs():
    """{pid: name} snapshot. Windows uses tasklist, POSIX reads /proc or ps."""
    if IS_WIN:
        try:
            r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                               capture_output=True, timeout=20)
            text = r.stdout.decode("mbcs", "replace")
            return parse_tasklist(text)
        except Exception:
            return {}
    procs = {}
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pid = int(entry)
                procs[pid] = _proc_name(pid)
        if procs:
            return procs
    except OSError:
        pass
    try:
        r = subprocess.run(["ps", "-eo", "pid=,comm="], capture_output=True,
                           text=True, timeout=10)
        for line in r.stdout.splitlines():
            bits = line.split(None, 1)
            if len(bits) == 2 and bits[0].isdigit():
                procs[int(bits[0])] = os.path.basename(bits[1].strip())
    except Exception:
        pass
    return procs


def collect():
    """Return (records, pid->name map) for this machine."""
    if IS_WIN:
        try:
            r = subprocess.run(["netstat", "-ano"], capture_output=True, timeout=30)
        except Exception as e:
            raise SystemExit("netstat failed: %s" % e)
        text = r.stdout.decode("mbcs", "replace")
        records = parse_netstat(text)
        return records, _all_procs()

    if IS_MAC:
        try:
            r = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"],
                               capture_output=True, text=True, timeout=30)
            records = parse_lsof(r.stdout)
        except Exception:
            records = []
        try:
            r2 = subprocess.run(["netstat", "-an", "-p", "udp"], capture_output=True,
                                text=True, timeout=20)
            records += parse_netstat(r2.stdout)
        except Exception:
            pass
        return records, _all_procs()

    # Linux: /proc/net/tcp is cheap and does not need lsof installed
    records = []
    for path, proto, v6 in (("/proc/net/tcp", "tcp", False),
                            ("/proc/net/tcp6", "tcp6", True),
                            ("/proc/net/udp", "udp", False),
                            ("/proc/net/udp6", "udp6", True)):
        records += _read_proc_net(path, proto, v6)
    if not records:
        try:
            r = subprocess.run(["netstat", "-tunap"], capture_output=True,
                               text=True, timeout=30)
            records = parse_netstat(r.stdout)
        except Exception:
            pass
    return records, _all_procs()


def _read_proc_net(path, proto, v6):
    """Parse /proc/net/{tcp,udp}[6]. Columns are hex, addresses are little-endian."""
    out = []
    try:
        with open(path, "r", encoding="ascii", errors="replace") as f:
            lines = f.readlines()[1:]
    except OSError:
        return out
    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        local, _, state_hex, pid = parts[1], parts[2], parts[3], _int(parts[9])
        host_hex, _, port_hex = local.partition(":")
        port = int(port_hex, 16) if port_hex else None
        if not port:
            continue
        host = _hex_ip(host_hex, v6)
        state = "LISTENING" if proto.startswith("tcp") and state_hex.upper() == "0A" else ""
        out.append(Record(proto, host, port, state, pid or 0))
    return out


def _hex_ip(h, v6):
    """Linux stores IPv4 as one little-endian u32, IPv6 as 4 little-endian u32s."""
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return h
    if not v6 and len(raw) == 4:
        return "%d.%d.%d.%d" % (raw[3], raw[2], raw[1], raw[0])
    if v6 and len(raw) == 16:
        words = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
        import socket
        import binascii
        packed = b"".join(words)
        try:
            return socket.inet_ntop(socket.AF_INET6, packed)
        except Exception:
            return binascii.hexlify(packed).decode()
    return h


# --------------------------------------------------------------------------
# filtering / output
# --------------------------------------------------------------------------

def select(records, port=None, proto=None, listening_only=True, states=None):
    hits = []
    seen = set()
    for r in records:
        if port is not None and r.port != port:
            continue
        if proto and not r.proto.startswith(proto):
            continue
        if states is not None:
            if r.state not in states:
                continue
        elif listening_only:
            if not r.is_listen():
                continue
        else:
            # --all: keep real connections, drop TIME_WAIT / FIN_WAIT / CLOSE_WAIT.
            # Those are rotting sockets with no owner pid - dozens of them pile up
            # on a busy port and bury the two rows that actually matter.
            if r.state in DEAD_STATES:
                continue
        # Collapse duplicates on the local socket. Two rows that differ only in
        # the peer are the same server accepting two clients - listing both
        # says nothing about who owns the port.
        key = (r.proto, r.host, r.port, r.state, r.pid)
        if key in seen:
            continue
        seen.add(key)
        hits.append(r)
    # Order: listening first, then live connections, then the rest (UDP has no
    # state and sorts after TCP). Within a group, by protocol family then port -
    # same shape netstat prints, so the output is scannable.
    def _key(r):
        state_rank = 0 if r.state == "LISTENING" else (1 if r.state == "ESTABLISHED" else 2)
        proto_rank = 0 if r.proto.startswith("tcp") else 1
        return (state_rank, proto_rank, r.port, r.host)
    hits.sort(key=_key)
    return hits


def _fmt_table(rows):
    if not rows:
        return "no matching socket"
    # PEER only earns its column when at least one row has a real remote end.
    show_peer = any(r.get("peer") and not _wildcard_peer(r["peer"]) for r in rows)
    if show_peer:
        head = ("PROTO", "LOCAL", "STATE", "PID", "PROCESS", "PEER")
    else:
        head = ("PROTO", "LOCAL", "STATE", "PID", "PROCESS")
    body = []
    for d in rows:
        cells = [d["proto"], d["local"], d["state"] or "-",
                 str(d["pid"]) if d["pid"] else "-", d["process"] or "?"]
        if show_peer:
            peer = d.get("peer") or ""
            cells.append("-" if _wildcard_peer(peer) else peer)
        body.append(tuple(cells))
    widths = [max(len(head[i]), *(len(r[i]) for r in body)) for i in range(len(head))]
    lines = ["  ".join(head[i].ljust(widths[i]) for i in range(len(head))),
             "  ".join("-" * widths[i] for i in range(len(head)))]
    for r in body:
        lines.append("  ".join(r[i].ljust(widths[i]) for i in range(len(head))).rstrip())
    return "\n".join(lines)


def _emit(rows, as_json):
    if as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print(_fmt_table(rows))


# --------------------------------------------------------------------------
# kill
# --------------------------------------------------------------------------

def kill_pid(pid, force=False, assume_yes=False):
    if not pid:
        print("cannot kill: no pid", file=sys.stderr)
        return 2
    name = _proc_name(pid) or "?"
    if not assume_yes:
        sys.stderr.write("kill %s (pid %d)? [y/N] " % (name, pid))
        sys.stderr.flush()
        try:
            answer = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 2
        if answer not in ("y", "yes"):
            print("aborted")
            return 2
    try:
        if IS_WIN:
            ok, err = _win_kill(pid, force)
        else:
            os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
            ok, err = True, ""
    except ProcessLookupError:
        print("killed pid %d (already gone)" % pid)
        return 0
    except PermissionError:
        print("kill failed: access denied on pid %d (needs elevation?)" % pid,
              file=sys.stderr)
        return 2
    except Exception as e:
        print("kill failed: %s" % e, file=sys.stderr)
        return 2
    if not ok:
        if err:
            sys.stderr.write(err + "\n")
        print("failed pid %d%s" % (pid, " (" + name + ")" if name else ""))
        return 2
    print("killed pid %d%s" % (pid, " (" + name + ")" if name else ""))
    return 0


def _win_kill(pid, force):
    """taskkill wrapper. Returns (ok, stderr_text).

    Without /F, taskkill posts WM_CLOSE and waits - which only works for
    processes that own a window and pump messages. A console-less service or a
    background script ignores it and taskkill exits 1 with
    "只能强行终止这个进程". So a failed graceful attempt is retried with /F
    instead of being reported as a failure: the user asked to kill it, and
    there is no other lever on Windows.
    """
    def run(cmd):
        r = subprocess.run(cmd, capture_output=True, timeout=20)
        out = r.stdout.decode("mbcs", "replace").strip()
        err = r.stderr.decode("mbcs", "replace").strip()
        return r.returncode, out, err

    rc, out, err = run(["taskkill", "/PID", str(pid)] + (["/F"] if force else []))
    if rc == 0:
        return True, ""
    if not force:
        rc2, out2, err2 = run(["taskkill", "/PID", str(pid), "/F"])
        if rc2 == 0:
            return True, ""
        return False, err2 or out2 or err
    return False, err or out


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="portwho",
        description="Show which process owns a local port.",
        epilog="exit codes: 0 found, 1 nothing matched, 2 error",
    )
    p.add_argument("port", nargs="?", type=int,
                   help="port number to look up (omit with --list)")
    p.add_argument("-l", "--list", action="store_true",
                   help="list every listening socket")
    p.add_argument("-a", "--all", action="store_true",
                   help="include non-listening sockets (established, udp)")
    p.add_argument("-p", "--proto", choices=["tcp", "udp"],
                   help="restrict to one protocol")
    p.add_argument("-j", "--json", action="store_true", help="json output")
    p.add_argument("-k", "--kill", action="store_true",
                   help="terminate the owning process (asks for confirmation)")
    p.add_argument("-f", "--force", action="store_true",
                   help="with --kill: SIGKILL / taskkill /F")
    p.add_argument("-y", "--yes", action="store_true",
                   help="with --kill: do not prompt")
    p.add_argument("-V", "--version", action="version", version="portwho 1.0.0")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.port is None and not args.list:
        build_parser().print_help()
        return 2
    if args.port is not None and not (0 < args.port < 65536):
        print("port out of range: %d" % args.port, file=sys.stderr)
        return 2

    try:
        records, procs = collect()
    except SystemExit:
        raise
    except Exception as e:
        print("failed to read socket table: %s" % e, file=sys.stderr)
        return 2

    hits = select(records, port=args.port, proto=args.proto,
                  listening_only=not args.all)
    # UDP rows have no state; --all should still show them, default query should too
    if args.port is not None and not hits:
        hits = select(records, port=args.port, proto=args.proto, listening_only=False)

    rows = []
    for r in hits:
        name = procs.get(r.pid, "")
        if not name:
            name = _proc_name(r.pid)
        exe = _win_exe_path(r.pid) if (IS_WIN and r.pid) else ""
        rows.append(r.as_dict(name, exe))

    if args.kill:
        if not rows:
            if args.json:
                print("[]")
            else:
                print("no matching socket")
            return 1
        pids = sorted({d["pid"] for d in rows if d["pid"]})
        if not pids:
            print("socket found but pid unknown (need elevation?)", file=sys.stderr)
            return 2
        rc = 0
        for pid in pids:
            rc = max(rc, kill_pid(pid, force=args.force, assume_yes=args.yes))
        return rc

    _emit(rows, args.json)
    return 0 if rows else 1


if __name__ == "__main__":
    sys.exit(main())

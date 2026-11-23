# portwho

Tell me which process is holding a port. One file, no dependencies,
Windows / Linux / macOS.

```
$ portwho 8082
PROTO  LOCAL         STATE      PID    PROCESS
-----  ------------  ---------  -----  -------
tcp    0.0.0.0:8082  LISTENING  13784  QQ.exe
```

## Why

`netstat -ano` prints 500 lines and you still have to guess which pid is the
one you want. `portwho 8082` prints one line.

## Install

No install. One file:

```bash
curl -O https://raw.githubusercontent.com/SusieCommons/portwho/main/portwho.py
python portwho.py 8082
```

Put it on PATH if you want the bare name to work:

```bash
chmod +x portwho.py && mv portwho.py ~/.local/bin/portwho
```

Windows: rename to `portwho.py` and either call `python portwho.py 8082` or
drop it next to a `portwho.cmd` containing `@python "%~dp0portwho.py" %*`.

## Usage

```
portwho PORT                 who owns PORT
portwho --list               every listening socket
portwho --list --all         include established connections and UDP
portwho -P NAME              the other direction: every port NAME holds
portwho PORT --json          machine readable
portwho PORT --kill          terminate the owner (asks first)
portwho PORT --kill -y -f    terminate without asking, force
```

`-P` matches on the process name as a case-insensitive substring, and falls
back to the full exe path when the name is not resolved. So `portwho -P qq`
finds both `QQ.exe` and `QQLiveService.exe`, and `portwho -P redis` still works
when the process runs from `C:\tools\redis-server.exe` under a different
display name.

| flag | meaning |
| --- | --- |
| `-l, --list` | list all listening sockets |
| `-a, --all` | include established / UDP; `TIME_WAIT` noise is dropped |
| `-p, --proto {tcp,udp}` | restrict to one protocol |
| `-P, --process NAME` | reverse lookup by process name |
| `-j, --json` | JSON output |
| `-k, --kill` | terminate the owning process, with confirmation |
| `-f, --force` | with `--kill`: `SIGKILL` / `taskkill /F` |
| `-y, --yes` | with `--kill`: skip the prompt |
| `-V, --version` | version |

Exit codes: `0` found, `1` nothing matched, `2` error. So this works:

```bash
if portwho 8080 >/dev/null; then echo "in use"; fi
```

## What it reads

| platform | source |
| --- | --- |
| Windows | `netstat -ano` + `tasklist /FO CSV /NH` |
| Linux | `/proc/net/{tcp,tcp6,udp,udp6}`, falls back to `netstat -tunap` |
| macOS | `lsof -nP -iTCP -sTCP:LISTEN -Fpcn` + `netstat -an -p udp` |

Process names on Windows come from `QueryFullProcessImageNameW` with
`PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`), which does not need
`SeDebugPrivilege` for same-user processes. Rows owned by another user or by
`SYSTEM` still show up, but the process name may be blank - that is expected
without elevation, not a bug.

## Details that took work

**Two netstat dialects.** Windows prints
`tcp local foreign STATE pid`; Linux prints
`tcp RecvQ SendQ local foreign STATE pid/prog`. Counting columns and hoping is
not reliable, so the shape is detected per line by checking whether columns 1
and 2 are both numeric.

**UDP has no state column.** On Linux the pid sits where the state would be on
TCP, so a single column map silently reads the state as the pid. The parser
keeps a separate index for UDP rows.

**IPv6 needs brackets.** `::1:5432` is ambiguous; the output prints
`[::1]:5432`.

**Listening rows still have a foreign column.** It is the wildcard
`0.0.0.0:0` / `*:*`, not a real peer. Treating "has a foreign address" as
"is established" makes every listening socket disappear.

**`--all` was drowning in `TIME_WAIT`.** A busy local port accumulates dozens
of dead sockets with no owning pid. They are filtered out; `ESTABLISHED` rows
are collapsed to one per local socket, since two rows differing only in the
peer means one server accepting two clients.

**Linux stores addresses little-endian.** `/proc/net/tcp` holds IPv4 as one
reversed u32 and IPv6 as four reversed u32s - the hex for loopback reads
`0100007F`, and reading it left to right gives you the octets backwards.

**Windows `taskkill` without `/F` cannot kill most things.** It posts
`WM_CLOSE` and waits, which only works for a process that owns a window and
pumps messages. A console-less background process ignores it and taskkill
exits 1 with `只能强行终止这个进程`. So `--kill` tries graceful, then escalates
to `/F` automatically - the other path just fails on Windows.

## Tests

```bash
python -m pytest tests/ -q
```

45 tests, fixture based - no live sockets, no admin rights needed. The
fixtures are real `netstat` / `tasklist` / `lsof` output captured on a zh-CN
Windows 10 box, a Debian container, and a Mac. The kill-escalation tests stub
out `subprocess.run`, so they never touch a real process.

The one thing tests cannot cover is whether the OS table is read correctly on
a real machine, so check that by hand: start something that listens, then

```bash
python portwho.py <that port>
```

You should get one row with the right pid in it.

## Limits

- `--kill` on Windows shells out to `taskkill`; on POSIX it sends
  `SIGTERM`, or `SIGKILL` with `-f`.
- Process names for sockets owned by other users need elevation.
- It reports what the OS reports. If the pid is `0`, nothing owned the socket
  at the moment it was read - common for sockets in teardown.

## License

MIT

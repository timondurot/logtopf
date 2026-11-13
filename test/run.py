#!/usr/bin/env python3
"""Black-box scenarios for logtopf, run against the FreeBSD test VM (test/vm.sh).

    test/run.py [scenario ...]          default: all
    test/run.py --label before          also saves metrics to test/vm/metrics-before.json

logtopf runs inside tmux (screen-256color) under script(1), so we can read the
rendered screen as text and count the raw bytes it sends to the terminal.
"""
import json, os, re, shlex, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
VMSH = os.path.join(HERE, "vm.sh")

PF_CONF = r"""
set skip on { lo0 vtnet0 }
pass in  on epair0a no state
pass in  log on epair0a proto tcp to port { 80 443 8080 } flags any no state
pass in  log on epair0a proto tcp from port { 80 443 } flags any no state
block in log on epair0a proto udp to port 9
match in log on epair0a proto udp to port 53
pass in  log on epair0a proto { icmp icmp6 } no state
pass in  log on epair0a from 198.18.0.30 no state   # fragments only match port-less rules
pass out log on epair0a no state
"""

NET_SETUP = r"""
set -e
kldload -n if_epair
ifconfig epair0a >/dev/null 2>&1 || ifconfig epair0 create >/dev/null
ifconfig epair0b up
ifconfig epair0a inet 10.99.0.1/24 up
ifconfig epair0a inet6 -ifdisabled fd00:99::1/64 2>/dev/null || true
MB=$(ifconfig epair0b ether | awk '/ether/{print $2}')
route -q delete -net 198.18.0.0/15 >/dev/null 2>&1 || true
route -q add -net 198.18.0.0/15 10.99.0.2
arp -s 10.99.0.2 $MB >/dev/null 2>&1 || true
route -q -6 delete fd00:98::/64 >/dev/null 2>&1 || true
route -q -6 add fd00:98::/64 fd00:99::2
ndp -s fd00:99::2 $MB >/dev/null 2>&1 || true
sysctl -q net.inet.tcp.blackhole=2 net.inet.udp.blackhole=1 >/dev/null
cat > /root/pf-test.conf <<'EOF'
%s
EOF
pfctl -q -f /root/pf-test.conf
pfctl -q -e 2>/dev/null || true
printf 'set -g default-terminal screen-256color\nset -g status off\n' > /root/tmux.conf
grep -q five.test /etc/hosts || printf '198.18.0.5 five.test\n10.99.0.1 gw.test\nfd00:98::5 six.test\n' >> /etc/hosts
ifconfig epair0a ether | awk '/ether/{print $2}'
""" % PF_CONF


def vm(cmd, check=True, timeout=120):
    for attempt in range(4):  # 255 = ssh itself failed (e.g. sshd MaxStartups), not the command
        r = subprocess.run([VMSH, "ssh", cmd], capture_output=True, text=True, timeout=timeout)
        if r.returncode != 255:
            break
        time.sleep(0.5 * (attempt + 1))
    if check and r.returncode != 0:
        raise RuntimeError(f"vm cmd failed ({r.returncode}): {cmd}\n{r.stdout}{r.stderr}")
    return r.stdout


class TUI:
    def __init__(self, cols=200, rows=50):
        self.cols, self.rows = cols, rows

    def start(self, resolve=False):
        vm("tmux -f /root/tmux.conf kill-server 2>/dev/null; pkill -x logtopf; rm -f /tmp/tty.raw; true", check=False)
        vm(f"tmux -f /root/tmux.conf new -d -s t -x {self.cols} -y {self.rows} "
           f"'script -q -t 0 /tmp/tty.raw /root/src/logtopf pflog0; sleep 3600'")
        time.sleep(1.5)
        if not resolve:
            self.keys("r")
        time.sleep(1.2)

    def stop(self):
        vm("tmux -f /root/tmux.conf send-keys -t t q; sleep 0.5; tmux -f /root/tmux.conf kill-server; pkill -x logtopf; true",
           check=False)

    def keys(self, *k):
        vm("tmux -f /root/tmux.conf send-keys -t t " + " ".join(map(shlex.quote, k)))

    def resize(self, cols, rows):
        vm(f"tmux -f /root/tmux.conf resize-window -t t -x {cols} -y {rows}")
        self.cols, self.rows = cols, rows

    def screen(self):
        return vm("tmux -f /root/tmux.conf capture-pane -p -t t").rstrip("\n").split("\n")

    def tty_bytes(self):
        return int(vm("stat -f %z /tmp/tty.raw").strip())

    def alive(self):
        return vm("pgrep -x logtopf", check=False).strip() != ""

    def cpu(self):
        out = vm("ps -o %cpu= -p $(pgrep -x logtopf)", check=False).split()
        return float(out[0]) if out else -1.0

    def table(self):
        """Parse flow rows into dicts using the column header positions."""
        lines = self.screen()
        hdr_i = next((i for i, l in enumerate(lines) if l.startswith("DIR") and "SRC" in l), None)
        if hdr_i is None:
            return lines, []
        hdr = lines[hdr_i]
        names = ["DIR", "SRC", "DST", "PROTO", "PORT", "RULE", "IFACE", "PKTS", "BYTES", "RATE", "AGE", "ACTION"]
        starts = [hdr.index(n) for n in names]
        rows = []
        for l in lines[hdr_i + 2:]:
            if not l.strip():
                continue
            row = {}
            for j, n in enumerate(names):
                end = starts[j + 1] if j + 1 < len(names) else None
                row[n] = l[starts[j]:end].strip()
            rows.append(row)
        return lines, rows

    def status(self):
        lines = self.screen()
        m = re.search(r"flows: (\d+)", lines[0]) if lines else None
        t = re.search(r"\d\d:\d\d:\d\d", lines[0]) if lines else None
        return (int(m.group(1)) if m else -1), (t.group(0) if t else None), lines[0] if lines else ""


def pktgen(args, bg=False):
    cmd = f"/root/pktgen -i epair0b -d {MAC} {args}"
    if bg:
        vm(f"(nohup {cmd} >/tmp/pktgen.out 2>&1 &) ; true")
        return []
    out = vm(cmd, timeout=300)
    return [l.split() for l in out.strip().split("\n") if l.strip()]


UNITS = {"B": 1, "KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3, "KB": 1e3, "MB": 1e6, "GB": 1e9}


def human(s):
    m = re.match(r"([\d.]+)\s*([KMG]i?B|B)", s)
    return float(m.group(1)) * UNITS[m.group(2)] if m else None


class Result:
    def __init__(self, name):
        self.name, self.fails, self.notes, self.metrics = name, [], [], {}

    def check(self, cond, msg):
        if not cond:
            self.fails.append(msg)
        return cond

    def note(self, msg):
        self.notes.append(msg)


# --------------------------------------------------------------------------- scenarios

def s_basic(t, r):
    """IPv4/IPv6 TCP flows: counts, ports, direction, iface; grouping of client ports."""
    t.start()
    sent = pktgen("-n 12 -c 40 -l 100 -P 80")                    # 12 clients -> :80
    sent6 = pktgen("-6 -o 300 -n 4 -c 25 -l 60 -P 443")                 # 4 v6 clients -> :443
    grp = pktgen("-o 100 -m sport -n 8 -c 5 -l 10 -P 8080")             # 1 client, 8 conns -> :8080
    rep = pktgen("-o 200 -R -n 3 -c 7 -l 10 -P 443")                    # replies from :443
    time.sleep(2.2)
    lines, rows = t.table()
    r.metrics["rows"] = len(rows)
    by_src = {}
    for row in rows:
        by_src.setdefault(row["SRC"], []).append(row)

    for s, d, sp, dp, n, b in sent:
        got = by_src.get(s, [])
        if r.check(len(got) == 1, f"v4 {s}: expected 1 row, got {len(got)}"):
            g = got[0]
            r.check(g["PKTS"] == n, f"v4 {s}: PKTS {g['PKTS']} != {n}")
            r.check(g["PORT"] == "http", f"v4 {s}: PORT {g['PORT']!r} != 'http'")
            r.check(g["DIR"] == "In" and g["ACTION"] == "pass" and g["IFACE"] == "epair0a",
                    f"v4 {s}: DIR/ACTION/IFACE {g['DIR']}/{g['ACTION']}/{g['IFACE']}")
    for s, d, sp, dp, n, b in sent6:
        got = by_src.get(s, [])
        if r.check(len(got) == 1, f"v6 {s}: expected 1 row, got {len(got)}"):
            r.check(got[0]["PKTS"] == n and got[0]["PORT"] == "https",
                    f"v6 {s}: PKTS/PORT {got[0]['PKTS']}/{got[0]['PORT']}")
    # one client opening 8 connections to :8080 should aggregate into one row on the server port
    g = [x for x in rows if x["SRC"] == grp[0][0] and x["PORT"] not in ("https",)]
    r.check(len(g) == 1 and g[0]["PKTS"] == "40" and g[0]["PORT"] in ("http-alt", "8080"),
            f"grouping: 1 client x 8 conns to :8080 -> {[(x['PORT'], x['PKTS']) for x in g]}")
    # replies from :443 (sport 443) should show 443 too
    for s, d, sp, dp, n, b in rep:
        got = [x for x in by_src.get(s, []) if x["PORT"] == "https"]
        r.check(len(got) == 1, f"reply {s}: no single https row: {[x['PORT'] for x in by_src.get(s, [])]}")
    r.check(all(x["DST"] for x in rows), "empty DST cell")
    t.stop()


def s_actions(t, r):
    """block / match actions, ICMP, IPv6 ext header, IPv4 fragments."""
    t.start()
    pktgen("-p udp -n 2 -c 3 -P 9")          # blocked
    pktgen("-o 10 -p udp -n 2 -c 3 -P 53 -l 20")   # match rule, then default pass (unlogged)
    pktgen("-o 20 -p icmp -n 1 -c 4")
    pktgen("-6 -H -n 1 -c 5 -P 80")          # v6 hop-by-hop then tcp
    pktgen("-o 30 -F -n 1 -c 6 -l 400 -P 8080")    # v4 tcp in two fragments each
    time.sleep(2.2)
    lines, rows = t.table()
    act = {(x["PROTO"], x["PORT"]): x["ACTION"] for x in rows}
    r.note("rows: " + ", ".join(f"{x['SRC']} {x['PROTO']}/{x['PORT']} {x['ACTION']} {x['PKTS']}" for x in rows))
    r.check(any(x["PORT"] in ("discard", "9") and x["ACTION"] == "block" for x in rows), "udp/9 not shown as block")
    dns = [x for x in rows if x["PORT"] in ("domain", "53")]
    r.check(dns and all(x["ACTION"] == "match" for x in dns), f"udp/53 match rule shows {[x['ACTION'] for x in dns]}")
    r.check(any(x["PROTO"] == "icmp" and x["PORT"] == "-" for x in rows), "icmp row missing / has port")
    v6 = [x for x in rows if x["SRC"] == "fd00:98::1"]
    r.check(v6 and all(x["PROTO"] == "tcp" and x["PORT"] == "http" for x in v6),
            f"v6+HBH shows {[(x['PROTO'], x['PORT']) for x in v6]}")
    junk = [x for x in rows if x["PORT"] in ("30840",)]   # 0x7878 = payload bytes read as ports
    r.check(not junk, f"fragment payload parsed as ports: {len(junk)} junk rows")
    t.stop()


def s_stress(t, r):
    """Many flows from one source (one shard) + table overflow: must stay alive and responsive."""
    t.start()
    pktgen("-o 50 -m dst -n 300 -c 2 -P 80")                    # 300 flows, one source
    time.sleep(2.2)
    n0, _, _ = t.status()
    _, rows = t.table()
    r.check(n0 == 300 and rows and all(x["PKTS"] == "2" for x in rows),
            f"300 flows from one source: count {n0}, PKTS {sorted(set(x['PKTS'] for x in rows))}")
    pktgen("-m dst -n 3000 -c 2 -P 80")
    pktgen("-m dst -n 6000 -c 1 -P 443")
    pktgen("-n 4000 -c 1 -P 80")
    time.sleep(2.5)
    alive = t.alive()
    n1, ts1, _ = t.status()
    time.sleep(2.2)
    n2, ts2, line = t.status()
    r.metrics.update(flows=n2)
    r.check(alive and t.alive(), "logtopf died")
    r.check(ts1 != ts2 and ts2 is not None, f"UI frozen (clock {ts1} -> {ts2})")
    r.check(0 < n2 <= 2048, f"flow count {n2}")
    r.note(f"status: {line.strip()}")
    for _ in range(3):
        t.keys("Down")
    time.sleep(0.5)
    r.check(t.alive(), "died while scrolling")
    t.stop()


def s_clear(t, r):
    """x clears the table while traffic is flowing; the live flow must come back."""
    t.start()
    pktgen("-n 1 -c 12000 -r 2000 -l 50 -P 80", bg=True)
    time.sleep(2)
    t.keys("x")
    time.sleep(2.5)
    lines, rows = t.table()
    live = [x for x in rows if x["SRC"] == "198.18.0.0"]
    r.check(len(live) == 1, f"live flow rows after clear: {len(live)}")
    if live:
        p1 = int(live[0]["PKTS"])
        time.sleep(1.2)
        _, rows2 = t.table()
        live2 = [x for x in rows2 if x["SRC"] == "198.18.0.0"]
        r.check(live2 and int(live2[0]["PKTS"]) > p1, "live flow not counting after clear")
    vm("pkill -x pktgen; true", check=False)
    t.stop()


def s_rate(t, r):
    """Constant 1000 pps x 1000 B payload: RATE ~= 976.6KiB (headers excluded), then decays to 0."""
    t.start()
    pktgen("-n 1 -c 9000 -r 1000 -l 1000 -P 80", bg=True)
    samples = []
    for _ in range(5):
        time.sleep(1.0)
        _, rows = t.table()
        x = [y for y in rows if y["SRC"] == "198.18.0.0"]
        if x:
            samples.append(human(x[0]["RATE"]) or 0)
    want = 1000 * 1000
    good = [s for s in samples[1:] if abs(s - want) / want < 0.05]
    r.metrics["rate_samples"] = samples
    r.check(len(good) >= len(samples[1:]) - 1, f"rate off: {[round(s) for s in samples]} want ~{want}")
    t.keys("3")
    t.keys("4")
    time.sleep(2.2)
    _, rows = t.table()
    x = [y for y in rows if y["SRC"] == "198.18.0.0"]
    with_hdr = human(x[0]["RATE"]) if x else 0
    r.check(with_hdr and abs(with_hdr - 1040000) / 1040000 < 0.05, f"rate with L3+L4: {with_hdr} want ~1040000")
    vm("pkill -x pktgen; true", check=False)
    time.sleep(3.5)
    _, rows = t.table()
    x = [y for y in rows if y["SRC"] == "198.18.0.0"]
    r.check(x and x[0]["RATE"] in ("0B",), f"rate after stop: {x[0]['RATE'] if x else None}")
    t.stop()


def s_render(t, r):
    """Terminal bytes: steady-state refresh and per scroll step, 200x50 and 80x24."""
    for cols, rows_ in ((200, 50), (80, 24)):
        t.cols, t.rows = cols, rows_
        t.start()
        pktgen("-n 120 -c 3 -P 80")
        pktgen("-n 1 -c 20000 -r 1000 -P 443", bg=True)   # one live flow so something changes each second
        time.sleep(2.5)
        b0 = t.tty_bytes()
        time.sleep(5)
        b1 = t.tty_bytes()
        idle = (b1 - b0) / 5
        for _ in range(20):
            t.keys("Down")
            time.sleep(0.06)
        time.sleep(0.4)
        b2 = t.tty_bytes()
        scroll = (b2 - b1 - idle * 1.6) / 20
        r.metrics[f"{cols}x{rows_}_refresh_Bps"] = round(idle)
        r.metrics[f"{cols}x{rows_}_scroll_B_per_step"] = round(scroll)
        r.metrics[f"{cols}x{rows_}_cpu"] = t.cpu()
        lines = t.screen()
        r.check(len(lines) <= rows_ and all(len(l) <= cols for l in lines), "screen overflow")
        vm("pkill -x pktgen; true", check=False)
        t.stop()


def s_resolve(t, r):
    """Hostnames from /etc/hosts show up; a flood of unresolvable hosts can't wedge the UI."""
    t.start(resolve=True)
    pktgen("-o 5 -n 1 -c 3 -P 80")
    pktgen("-6 -o 4 -n 1 -c 3 -P 80")
    time.sleep(3.3)
    _, rows = t.table()
    r.check(any(x["SRC"] == "five.test" and x["DST"] == "gw.test" for x in rows),
            f"v4 names: {[(x['SRC'], x['DST']) for x in rows]}")
    r.check(any(x["SRC"] == "six.test" for x in rows), "v6 name from /etc/hosts not shown")
    pktgen("-o 1000 -n 5000 -c 1 -P 443")
    time.sleep(2.5)
    _, ts1, _ = t.status()
    time.sleep(2.2)
    n, ts2, _ = t.status()
    r.check(t.alive() and ts1 != ts2, f"UI stalled with 5000 hosts ({ts1} -> {ts2})")
    t.stop()


def s_narrow(t, r):
    """80 columns: rows are clipped, not wrapped onto the next line; ? shows and hides the keys."""
    t.cols, t.rows = 80, 14
    t.start()
    pktgen("-n 3 -c 3 -P 443 -l 900")
    time.sleep(2.2)
    lines = t.screen()
    r.check(all(not l.strip() for l in lines[7:]), f"text below the last row: {[l.strip() for l in lines[7:] if l.strip()]}")
    t.keys("?")
    time.sleep(0.6)
    r.check("any key closes" in "".join(t.screen()), "? did not show the keys")
    t.keys("j")
    time.sleep(0.6)
    after = t.screen()
    r.check("any key closes" not in "".join(after) and all(not l.strip() for l in after[7:]),
            "key overlay left behind")
    t.stop()


SCENARIOS = {"basic": s_basic, "actions": s_actions, "stress": s_stress,
             "clear": s_clear, "rate": s_rate, "resolve": s_resolve, "narrow": s_narrow, "render": s_render}


def main():
    global MAC
    args = sys.argv[1:]
    label = None
    if "--label" in args:
        i = args.index("--label")
        label = args[i + 1]
        del args[i:i + 2]
    names = args or list(SCENARIOS)
    MAC = vm(NET_SETUP).strip().split("\n")[-1]
    results, ok = {}, True
    for n in names:
        r = Result(n)
        t0 = time.time()
        try:
            SCENARIOS[n](TUI(), r)
        except Exception as e:  # keep going; a crash is a failure of that scenario
            r.fails.append(f"exception: {e}")
            vm("tmux -f /root/tmux.conf kill-server; pkill -x logtopf; pkill -x pktgen; true", check=False)
        status = "PASS" if not r.fails else "FAIL"
        ok &= not r.fails
        print(f"[{status}] {n:8s} {time.time() - t0:5.1f}s {json.dumps(r.metrics) if r.metrics else ''}")
        for f in r.fails:
            print(f"    - {f}")
        for x in r.notes:
            print(f"    . {x}")
        results[n] = {"fails": r.fails, "metrics": r.metrics, "notes": r.notes}
    if label:
        with open(os.path.join(HERE, "vm", f"metrics-{label}.json"), "w") as f:
            json.dump(results, f, indent=1)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

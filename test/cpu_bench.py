#!/usr/bin/env python3
"""What does logtopf cost in CPU and memory? Runs inside the test VM.

    cpu_bench.py --mac <epair0a mac> [--seconds 15]

logtopf (in tmux, default settings), pflogd (the base system's logger, already
running) and `tcpdump -n -e -i pflog0 > /dev/null` all read pflog0 at the same
time, so each gets exactly the same packets. For each load we take the user +
system CPU time each process used over the window (procstat -r), and count the
packets pf logged from pflog0's interface counter.

Loads: idle with an empty table, idle with a full 2048-flow table, then 1k,
10k and 100k packets/s spread over 500 flows, 100k/s where every packet is a
new flow (a scan or flood: the table evicts on every packet), and as fast as
the generator can write, over 500 flows and as new flows. The generator runs
on the last CPU. pflogd's log is emptied before each load so the disk never
fills. --no-tcpdump leaves tcpdump out, e.g. on a single CPU where it would
take the whole machine.
Needs: python3, /root/pktgen, tmux, pf + epair set up by test/run.py.
"""
import argparse, json, os, re, subprocess, time

ap = argparse.ArgumentParser()
ap.add_argument("--mac", required=True)
ap.add_argument("--seconds", type=float, default=15)
ap.add_argument("--bin", default="/root/src/logtopf")
ap.add_argument("--json")
ap.add_argument("--no-tcpdump", action="store_true")
args = ap.parse_args()

NCPU = os.cpu_count()
TMUX = ["tmux", "-f", "/root/tmux.conf"]


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def pids(pattern):
    return [int(p) for p in sh(f"pgrep -f '{pattern}'").split()]


def cpu_and_rss(pid_list):
    """Total user+sys seconds and current RSS (KiB) of the given processes."""
    total, rss = 0.0, 0
    for pid in pid_list:
        for line in sh(f"procstat -r {pid}").splitlines():
            m = re.search(r"(user|system) time\s+(\d+):(\d+):(\d+\.\d+)", line)
            if m:
                total += int(m.group(2)) * 3600 + int(m.group(3)) * 60 + float(m.group(4))
        out = sh(f"ps -o rss= -p {pid}").strip()
        rss += int(out) if out.isdigit() else 0
    return total, rss


def logged_packets():
    lines = sh("netstat -I pflog0 -bn").splitlines()
    return int(lines[1].split()[8])


def pktgen(rate, count, flows):
    pin = f"cpuset -l {NCPU - 1} " if NCPU > 1 else ""
    return subprocess.Popen(
        f"exec {pin}/root/pktgen -i epair0b -d {args.mac} -n {flows} -c {count} -P 80 -l 400 -r {rate}",
        shell=True, stdout=subprocess.DEVNULL)


def drops():
    top = sh(" ".join(TMUX) + " capture-pane -p -t b").split("\n")[0]
    m = re.search(r"KRN:(\d+) APP:(\d+)", top)
    return (int(m.group(1)), int(m.group(2))) if m else (None, None)


sh(" ".join(TMUX) + " kill-server; pkill -x logtopf; pkill -x tcpdump; pkill -x pktgen")
sh(" ".join(TMUX) + f" new -d -s b -x 200 -y 50 '{args.bin}'")
tcpdump = None
if not args.no_tcpdump:
    tcpdump = subprocess.Popen("exec tcpdump -n -e -i pflog0 > /dev/null 2>&1", shell=True)
time.sleep(2)
procs = {"logtopf": pids(f"^{args.bin}"), "pflogd": pids("^pflogd")}
if tcpdump:
    procs["tcpdump"] = [tcpdump.pid]

NEW = 65536  # more flows than table slots, sent round-robin: each packet is a miss
loads = [("idle, empty table", None, 0), ("idle, 2048 flows", "fill", 2100),
         ("1k pkt/s", 1000, 500), ("10k pkt/s", 10000, 500), ("100k pkt/s", 100000, 500),
         ("100k pkt/s, all new flows", 100000, NEW),
         ("max", 0, 500), ("max, all new flows", 0, NEW)]
results = []
for name, rate, flows in loads:
    sh(": > /var/log/pflog")
    gen = None
    if rate == "fill":
        pktgen(0, 2, flows).wait()  # every slot used
        time.sleep(1)
    elif rate is not None:
        total = rate * (args.seconds + 4) if rate else 200_000_000
        gen = pktgen(rate, int(total / flows) + 1, flows)
        time.sleep(2)
    before = {k: cpu_and_rss(v)[0] for k, v in procs.items()}
    pk0, t0 = logged_packets(), time.monotonic()
    time.sleep(args.seconds)
    after = {k: cpu_and_rss(v) for k, v in procs.items()}
    pk1, t1 = logged_packets(), time.monotonic()
    if gen:
        gen.kill()
        gen.wait()
    wall, pkts = t1 - t0, pk1 - pk0
    row = {"load": name, "pps": round(pkts / wall)}
    for k in procs:
        used = after[k][0] - before[k]
        row[f"{k}_cpu_pct"] = round(100 * used / wall, 2)
        row[f"{k}_us_per_pkt"] = round(1e6 * used / pkts, 2) if pkts > 1000 else None
        row[f"{k}_rss_mib"] = round(after[k][1] / 1024, 1)
    row["krn_drops"], row["app_drops"] = drops()
    results.append(row)
    print(json.dumps(row), flush=True)

sh(" ".join(TMUX) + " kill-server; pkill -x logtopf; : > /var/log/pflog")
if tcpdump:
    tcpdump.kill()
info = {"ncpu": NCPU, "mem_mib": int(sh("sysctl -n hw.physmem")) // 2**20,
        "cpu": sh("sysctl -n hw.model").strip(), "rows": results}
if args.json:
    with open(args.json, "w") as f:
        json.dump(info, f, indent=1)

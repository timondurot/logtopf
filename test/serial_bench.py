#!/usr/bin/env python3
"""How does logtopf feel over a slow or flaky serial line? Runs inside the test VM.

logtopf runs on a pseudo-terminal whose line speed is set to the baud rate (that
also sizes the kernel's output queue, as for a real port). This script is the
terminal at the other end: it drains the pty at exactly baud/10 bytes per second
(8N1), so output queues up in logtopf's tty and its writes block, the way they do
behind a real UART, and it feeds what it reads into a pyte terminal emulator.
(nmdm(4) is no good for this: a slow reader makes it drop bytes.)

    serial_bench.py --mac <epair0a mac> [--baud 9600] [--cols 80 --rows 24] [--flaky]

Measures, for a table of ~150 flows (4 of them live) sorted by source:
  refresh   bytes/s the 1 Hz refresh needs, as a share of the line
  backlog   output queued between logtopf and the screen, in seconds of line time
  step      key press -> whole screen shows the new scroll position (single presses)
  hold      after holding Down at 30 keys/s for 3 s: release -> final position shown
  wrong     rows still wrong 6 s after the last key (flaky mode garbles bytes),
            and (flaky) after pressing Ctrl-L
--flaky adds random stalls (50-500 ms, ~1 per 2 s) and byte errors (1 in 4000).
Needs: python3, pyte, /root/pktgen, pf + epair set up by test/run.py.
--raw saves the received byte stream, e.g. to replay it into tmux.
"""
import argparse, fcntl, json, os, random, statistics, struct, subprocess, sys, termios, threading, time, tty

import pyte

ap = argparse.ArgumentParser()
ap.add_argument("--mac", required=True)
ap.add_argument("--baud", type=int, default=9600)
ap.add_argument("--cols", type=int, default=80)
ap.add_argument("--rows", type=int, default=24)
ap.add_argument("--flaky", action="store_true")
ap.add_argument("--bin", default="/root/src/logtopf")
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--json")
ap.add_argument("--raw", help="save the byte stream the terminal received")
args = ap.parse_args()
random.seed(args.seed)

DOWN, LEFT = b"\x1bOB", b"\x1bOD"
BPS = args.baud / 10.0


master, slave = os.openpty()
tty.setraw(slave)
attrs = termios.tcgetattr(slave)
attrs[4] = attrs[5] = args.baud
termios.tcsetattr(slave, termios.TCSANOW, attrs)
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", args.rows, args.cols, 0, 0))
os.set_blocking(master, False)


class Line(threading.Thread):
    """The far end of the cable: paced reader feeding a terminal emulator."""

    def __init__(self):
        super().__init__(daemon=True)
        self.screen = pyte.Screen(args.cols, args.rows)
        self.stream = pyte.ByteStream(self.screen)
        self.lock = threading.Lock()
        self.total = 0
        self.errors = 0
        self.stop = False

    def run(self):
        prev, credit, stall_until = time.monotonic(), 0.0, 0.0
        while not self.stop:
            now = time.monotonic()
            credit = min(credit + (now - prev) * BPS, BPS * 0.004 + 16)  # ~4 ms UART FIFO
            prev = now
            if args.flaky:
                if now < stall_until:
                    credit = 0.0
                    time.sleep(0.002)
                    continue
                if random.random() < 0.001:
                    stall_until = now + random.uniform(0.05, 0.5)
            want = int(credit)
            if want > 0:
                try:
                    data = os.read(master, want)
                except BlockingIOError:
                    data = b""
                if data:
                    credit -= len(data)
                    if args.flaky:
                        b = bytearray(data)
                        for i in range(len(b)):
                            if random.random() < 1 / 4000:
                                b[i] = random.randrange(256)
                                self.errors += 1
                        data = bytes(b)
                    if rawf:
                        rawf.write(data)
                    with self.lock:
                        self.stream.feed(data)
                        self.total += len(data)
            time.sleep(0.002)

    def display(self):
        with self.lock:
            return list(self.screen.display)


def queued():
    """Bytes written by logtopf but not yet on the screen."""
    return struct.unpack("i", fcntl.ioctl(slave, termios.TIOCOUTQ, struct.pack("i", 0)))[0]


rawf = open(args.raw, "wb", buffering=0) if args.raw else None
line = Line()
line.start()
env = dict(os.environ, TERM="screen-256color")
proc = subprocess.Popen([args.bin, "pflog0"], stdin=slave, stdout=slave, stderr=subprocess.DEVNULL,
                        env=env, start_new_session=True)


def key(k, times=1):
    for _ in range(times):
        os.write(master, k)


def shown_srcs():
    d = line.display()
    hdr = d[2] if len(d) > 2 else ""
    if "SRC" not in hdr or "DST" not in hdr:
        return []
    a, b = hdr.index("SRC"), hdr.index("DST")
    return [r[a:b].strip() for r in d[4:]]


def first_src():
    s = shown_srcs()
    return s[0] if s else None


def frame_is(pos):
    """Every flow row shows what it should at scroll position pos."""
    want = order[pos:pos + visible]
    return shown_srcs()[:len(want)] == want


def wait_for(pred, timeout):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if pred():
            return time.monotonic() - t0
        time.sleep(0.003)
    return None


def pktgen(a, bg=False):
    cmd = ["/root/pktgen", "-i", "epair0b", "-d", args.mac] + a.split()
    if bg:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL)
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [l.split()[0] for l in out.strip().split("\n")]


res = {"baud": args.baud, "size": f"{args.cols}x{args.rows}", "flaky": args.flaky, "bin": args.bin}
try:
    time.sleep(1.0)
    key(b"r")  # no DNS: keeps the screen deterministic
    srcs = pktgen("-o 1000 -n 150 -c 2 -P 80")
    live = []
    for i, r in enumerate((400, 150, 60, 25)):
        live.append(pktgen(f"-o {2000 + i} -R -P 443 -n 1 -c 100000000 -r {r} -l 700", bg=True))
    srcs += [f"198.18.{(2000 + i) >> 8}.{(2000 + i) & 255}" for i in range(4)]
    key(LEFT, 8)  # sort column RATE -> SRC
    order = sorted(srcs, reverse=True)  # sort_dir -1: descending
    visible = args.rows - 4
    max_pos = len(order) - visible

    if wait_for(lambda: first_src() == order[0], 90) is None:
        print("never settled; screen:\n" + "\n".join(line.display()), file=sys.stderr)
        sys.exit(1)
    time.sleep(3)

    b0, t0, qs = line.total, time.monotonic(), []
    while time.monotonic() - t0 < 10:
        qs.append(queued())
        time.sleep(0.1)
    rate = (line.total - b0) / (time.monotonic() - t0)
    res["refresh_Bps"] = round(rate)
    res["line_use_pct"] = round(100 * rate / BPS)
    res["backlog_s"] = round(statistics.mean(qs) / BPS, 2)

    pos, steps = 0, []
    for _ in range(5):
        pos += 1
        key(DOWN)
        steps.append(wait_for(lambda p=pos: frame_is(p), 8))
        if steps[-1] is None and not res.get("debug"):
            res["debug"] = {"want": order[pos:pos + visible], "got": shown_srcs(), "offset": line.total}
        time.sleep(1.3)
    ok = [s for s in steps if s is not None]
    res["step_ms_median"] = round(1000 * statistics.median(ok)) if ok else None
    res["step_ms_max"] = round(1000 * max(ok)) if ok else None
    res["step_missed"] = len(steps) - len(ok)

    presses = 90
    trace, t_hold = [], time.monotonic()
    for _ in range(presses):
        key(DOWN)
        time.sleep(1 / 30)
        if os.environ.get("TRACE"):
            fs = first_src()
            trace.append((round(time.monotonic() - t_hold, 2), queued(), order.index(fs) if fs in order else -1))
    if trace:
        res["trace"] = trace[::6]
    pos = min(pos + presses, max_pos)
    t = wait_for(lambda: frame_is(pos), 30)
    res["hold_release_to_final_ms"] = round(1000 * t) if t is not None else None

    time.sleep(6)
    want, got = order[pos:pos + visible], shown_srcs()
    res["wrong_rows"] = sum(1 for i, x in enumerate(want) if i >= len(got) or got[i] != x)
    if args.flaky:
        key(b"\x0c")  # Ctrl-L
        time.sleep(4 + 2500 / BPS)
        want, got = order[pos:pos + visible], shown_srcs()
        res["wrong_after_ctrl_l"] = sum(1 for i, x in enumerate(want) if i >= len(got) or got[i] != x)
    if res["wrong_rows"]:
        res["screen"] = line.display()
        res["want_first"] = want[:3]
    res["byte_errors"] = line.errors
    res["bytes_total"] = line.total
finally:
    for p in live if "live" in dir() else []:
        p.kill()
    proc.terminate()
    try:
        proc.wait(2)
    except subprocess.TimeoutExpired:
        proc.kill()
    line.stop = True

print(json.dumps(res))
if args.json:
    with open(args.json, "a") as f:
        f.write(json.dumps(res) + "\n")

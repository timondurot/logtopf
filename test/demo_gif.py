#!/usr/bin/env python3
"""Record a scripted logtopf session in the test VM and render it to demo.gif.

    test/demo_gif.py                    record, then write demo.gif in the repo root
    RENDER_ONLY=1 test/demo_gif.py      re-render the last recording (test/vm/frames/)

The session: rates ticking, a few blocked scans and DNS lookups, a download
speeding up, a scan from 400 sources, re-sorting, scrolling, the key overlay,
and clearing the table. The screen is captured 5 times a second and drawn with
test/screenshot.py's renderer, light and dark split along the same diagonal.
"""
import glob, io, os, subprocess, sys, tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from screenshot import HOSTS, PF, diagonal, render
from PIL import Image

OUT = os.path.join(HERE, "..", "demo.gif")
FRAMES = os.path.join(HERE, "vm", "frames")
COLS, ROWS, SIZE, FPS = 120, 26, 16, 5

RECORD = r"""
T="tmux -f /root/tmux.conf"
MAC=$(ifconfig epair0a ether | awk '/ether/{print $2}')
G="/root/pktgen -i epair0b -d $MAC"
CLEAN="sed -i '' -e '/example\./d' -e '/router\.lan/d' -e '/gw\.test/d' /etc/hosts"
q() { "$@" >/dev/null 2>&1; }
bgq() { "$@" >/dev/null 2>&1 & }
k() { $T send-keys -t d "$@"; }

pkill -x pktgen; $T kill-server 2>/dev/null
eval "$CLEAN"
cat >> /etc/hosts <<'EOF'
%(hosts)s
EOF
cat > /root/pf-shot.conf <<'EOF'
%(pf)s
EOF
pfctl -q -f /root/pf-shot.conf

$T new -d -s d -x %(cols)d -y %(rows)d /root/src/logtopf
bgq $G -o 40 -R -P 443 -n 1 -c 100000000 -r 2600 -l 1400; DL=$!
bgq $G -o 41 -R -P 443 -n 1 -c 100000000 -r 900 -l 1200
bgq $G -6 -o 43 -R -P 443 -n 1 -c 100000000 -r 2100 -l 1200
bgq $G -o 45 -R -p udp -P 443 -n 1 -c 100000000 -r 700 -l 1200
bgq $G -o 42 -R -P 80 -n 1 -c 100000000 -r 160 -l 1400
bgq ping -i 0.5 198.18.0.42
q $G -o 47 -R -p udp -P 123 -n 1 -c 2 -l 48
sleep 4

rm -rf /tmp/frames; mkdir /tmp/frames; touch /tmp/rec.on
( i=0; while [ -f /tmp/rec.on ]; do
    $T capture-pane -e -p -t d > /tmp/frames/$(printf %%04d $i).ansi
    i=$((i + 1)); sleep %(interval)s
  done ) &
REC=$!

sleep 1.6
for p in 22 3389 23; do q $G -o $(jot -r 1 100 200) -P $p -n 1 -c 3; sleep 0.3; done
sleep 0.6
q $G -o 150 -p udp -P 53 -n 2 -c 3 -l 30
sleep 1.2
kill $DL; bgq $G -o 40 -R -P 443 -n 1 -c 100000000 -r 7800 -l 1400   # the download speeds up
sleep 2
bgq $G -o 1000 -n 400 -c 1 -P 23 -r 800                              # a scan from 400 sources
sleep 2.6
k Left; sleep 1.4                                                     # sort by bytes
k Left; sleep 1.6                                                     # sort by packets
for n in 1 2 3 4 5 6 7 8; do k Down; sleep 0.25; done
sleep 0.8
for n in 1 2 3 4 5 6 7 8; do k Up; sleep 0.15; done
sleep 0.6
k Right; k Right; sleep 1                                             # back to rate
k '?'; sleep 2.6                                                      # the key overlay
k Space; sleep 1.2
k x; sleep 3.2                                                        # clear: live flows come back

rm /tmp/rec.on; wait $REC
pkill -x pktgen; pkill -f 'ping -i'; $T kill-server
eval "$CLEAN"; echo '10.99.0.1 gw.test' >> /etc/hosts
pfctl -q -f /root/pf-test.conf
"""


def record():
    import run
    run.vm(run.NET_SETUP)
    script = RECORD % dict(hosts=HOSTS.strip(), pf=PF.strip(), cols=COLS, rows=ROWS, interval=1 / FPS)
    subprocess.run([run.VMSH, "ssh", "sh -s"], input=script, text=True, check=True, timeout=180,
                   stdout=subprocess.DEVNULL)
    tar = subprocess.run([run.VMSH, "ssh", "cd /tmp/frames && tar cf - ."], capture_output=True,
                         check=True).stdout
    os.makedirs(FRAMES, exist_ok=True)
    for old in glob.glob(os.path.join(FRAMES, "*.ansi")):
        os.remove(old)
    tarfile.open(fileobj=io.BytesIO(tar)).extractall(FRAMES, filter="data")


if __name__ == "__main__":
    if not os.environ.get("RENDER_ONLY"):
        sys.argv = ["x"]
        record()
    ansi = [open(f).read() for f in sorted(glob.glob(os.path.join(FRAMES, "*.ansi")))]
    frames = [diagonal(render(a, "light", COLS, ROWS, SIZE), render(a, "dark", COLS, ROWS, SIZE), line_px=3)
              for a in ansi]
    # one palette for all frames, so colours don't flicker
    picks = frames[::12]
    strip = Image.new("RGB", (frames[0].width, frames[0].height * len(picks)))
    for i, f in enumerate(picks):
        strip.paste(f, (0, i * f.height))
    pal = strip.quantize(256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    gif = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
    durations = [1000 // FPS] * len(gif)
    durations[-1] = 2500  # rest on the last frame before looping
    gif[0].save(OUT, save_all=True, append_images=gif[1:], duration=durations, loop=0,
                optimize=True, disposal=1)
    print(OUT, frames[0].size, len(gif), "frames", os.path.getsize(OUT) // 1024, "KiB")

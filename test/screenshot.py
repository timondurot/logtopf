#!/usr/bin/env python3
"""Stage demo traffic in the test VM, capture logtopf's screen with colours, render to PNG.

    test/screenshot.py                  capture, then write screenshot.png in the repo root:
                                        the light and dark renders, split along a diagonal
    RENDER_ONLY=1 test/screenshot.py    re-render the last capture (test/vm/screenshot.ansi)

render() and diagonal() are also used by test/demo_gif.py.
Needs Pillow and DejaVu Sans Mono. Hostnames are fake (example.* via /etc/hosts in the VM).
"""
import os, re, sys, time
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "screenshot.png")
COLS, ROWS = 172, 25

HOSTS = """
198.18.0.40 cdn.example.net
198.18.0.41 updates.example.org
198.18.0.42 mirror.example.com
fd00:98::2c video.example.com
198.18.0.45 quic.example.net
198.18.0.47 time.example.org
10.99.0.1 router.lan
fd00:99::1 router.lan
"""

PF = r"""
set skip on { lo0 vtnet0 }
pass in on epair0a no state
pass in log on epair0a proto tcp from port { 80 443 } no state
pass in log on epair0a proto udp from port { 123 443 } no state
block in log on epair0a proto tcp to port { 22 23 445 3389 }
block in log on epair0a proto udp to port { 161 1900 }
match in log on epair0a proto udp to port 53
pass in log on epair0a proto { icmp icmp6 } no state
pass out log on epair0a proto icmp no state
"""

THEMES = {
    "dark": dict(fg=(0xd0, 0xd0, 0xd0), bg=(0x16, 0x17, 0x19),
                 base=[(0x1d, 0x1f, 0x21), (0xcc, 0x66, 0x66), (0xb5, 0xbd, 0x68), (0xf0, 0xc6, 0x74),
                       (0x81, 0xa2, 0xbe), (0xb2, 0x94, 0xbb), (0x8a, 0xbe, 0xb7), (0xc5, 0xc8, 0xc6)]),
    "light": dict(fg=(0x24, 0x29, 0x2e), bg=(0xfa, 0xfa, 0xf8),
                  base=[(0x24, 0x29, 0x2e), (0xc0, 0x3a, 0x2b), (0x2f, 0x7d, 0x32), (0x9a, 0x6a, 0x00),
                        (0x2d, 0x5f, 0xa8), (0x8a, 0x3f, 0xa0), (0x1b, 0x7c, 0x83), (0xe8, 0xe8, 0xe4)]),
}
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SGR = re.compile(r"\x1b(?:\[([0-9;]*)m|\(([0B]))")
ACS = {"q": "─", "x": "│", "l": "┌", "k": "┐", "m": "└", "j": "┘"}


def xterm(theme, n):
    base = theme["base"]
    if n < 8:
        return base[n]
    if n < 16:
        return tuple(min(255, c + 60) for c in base[n - 8])
    if n < 232:
        n -= 16
        lv = [0, 95, 135, 175, 215, 255]
        return (lv[n // 36], lv[n // 6 % 6], lv[n % 6])
    g = 8 + (n - 232) * 10
    return (g, g, g)


def render(ansi, theme_name, cols=COLS, rows=ROWS, size=30):
    """Draw a `tmux capture-pane -e` dump as a terminal in the given theme.
    size is the font size in pixels; line height and padding scale with it."""
    theme = THEMES[theme_name]
    FG, BG = theme["fg"], theme["bg"]
    font, bold = ImageFont.truetype(FONT, size), ImageFont.truetype(BOLD, size)
    cw = int(round(font.getlength("M")))
    ch = round(size * 4 / 3)
    pad = round(size * 14 / 15)
    img = Image.new("RGB", (cols * cw + pad * 2, rows * ch + pad * 2), BG)
    dr = ImageDraw.Draw(img)
    for y, line in enumerate(ansi.rstrip("\n").split("\n")[:rows]):
        fg, bgc, b, x, pos, acs = FG, None, False, 0, 0, False
        for m in list(SGR.finditer(line)) + [None]:
            text = line[pos:m.start()] if m else line[pos:]
            for c in text:
                if c in "\x0e\x0f":
                    acs = c == "\x0e"
                    continue
                if acs:
                    c = ACS.get(c, c)
                px, py = pad + x * cw, pad + y * ch
                if bgc:
                    dr.rectangle([px, py, px + cw, py + ch], fill=bgc)
                if c != " ":
                    dr.text((px, py + size // 15), c, font=bold if b else font, fill=fg)
                x += 1
            if not m:
                break
            pos = m.end()
            if m.group(2):
                acs = m.group(2) == "0"
                continue
            codes = [int(c) if c else 0 for c in m.group(1).split(";")] or [0]
            i = 0
            while i < len(codes):
                c = codes[i]
                if c == 0:
                    fg, bgc, b = FG, None, False
                elif c == 1:
                    b = True
                elif c == 22:
                    b = False
                elif c == 38 and i + 2 < len(codes) and codes[i + 1] == 5:
                    fg = xterm(theme, codes[i + 2]); i += 2
                elif c == 48 and i + 2 < len(codes) and codes[i + 1] == 5:
                    bgc = xterm(theme, codes[i + 2]); i += 2
                elif c == 39:
                    fg = FG
                elif c == 49:
                    bgc = None
                elif 30 <= c <= 37:
                    fg = xterm(theme, c - 30)
                elif 40 <= c <= 47:
                    bgc = xterm(theme, c - 40)
                elif 90 <= c <= 97:
                    fg = xterm(theme, c - 90 + 8)
                i += 1
    return img


def diagonal(light, dark, line_px=5):
    """Light on the left, dark on the right, cut along a diagonal.
    Drawn at 4x and scaled down for a smooth edge."""
    W, H = light.size
    S = 4
    top, bottom = 0.60 * W, 0.40 * W  # where the cut meets the top and bottom edges
    cut = [(top * S, 0), (bottom * S, H * S)]
    mask = Image.new("L", (W * S, H * S), 0)
    ImageDraw.Draw(mask).polygon([(0, 0), cut[0], cut[1], (0, H * S)], fill=255)
    mask = mask.resize((W, H), Image.LANCZOS)
    img = Image.composite(light, dark, mask)
    line = Image.new("L", (W * S, H * S), 0)
    ImageDraw.Draw(line).line(cut, fill=255, width=line_px * S)
    line = line.resize((W, H), Image.LANCZOS)
    img.paste((138, 138, 138), (0, 0), line)
    return img


def capture():
    sys.argv = ["x"]
    sys.path.insert(0, HERE)
    import run
    run.MAC = run.vm(run.NET_SETUP).strip().split("\n")[-1]
    CLEAN = "sed -i '' -e '/example\\./d' -e '/router\\.lan/d' -e '/gw\\.test/d' /etc/hosts"
    run.vm(CLEAN + "; cat >> /etc/hosts <<'EOF'\n" + HOSTS + "EOF")
    run.vm("cat > /root/pf-shot.conf <<'EOF'\n" + PF + "EOF\npfctl -q -f /root/pf-shot.conf")

    t = run.TUI(COLS, ROWS)
    t.start(resolve=True)
    bg = [
        "-o 40 -R -P 443 -n 1 -c 400000 -r 5200 -l 1400",
        "-o 41 -R -P 443 -n 1 -c 400000 -r 900 -l 1200",
        "-o 42 -R -P 80 -n 1 -c 400000 -r 160 -l 1400",
        "-6 -o 43 -R -P 443 -n 1 -c 400000 -r 2100 -l 1200",
        "-o 45 -R -p udp -P 443 -n 1 -c 400000 -r 700 -l 1200",
    ]
    for a in bg:
        run.vm(f"(nohup /root/pktgen -i epair0b -d {run.MAC} {a} >/dev/null 2>&1 &); true")
    run.pktgen("-o 47 -R -p udp -P 123 -n 1 -c 4 -l 48")
    for i, port in enumerate((22, 23, 445, 3389, 22, 22)):
        run.pktgen(f"-o {100 + i * 7} -P {port} -n 1 -c {3 + i}")
    run.pktgen("-o 130 -p udp -P 1900 -n 2 -c 2")
    run.pktgen("-o 140 -p udp -P 161 -n 1 -c 5")
    run.pktgen("-o 150 -p udp -P 53 -n 3 -c 6 -l 30")
    run.pktgen("-o 160 -p icmp -n 2 -c 4")
    run.vm("(nohup ping -c 30 -i 0.25 198.18.0.42 >/dev/null 2>&1 &); true")
    time.sleep(7)
    ansi = run.vm("tmux -f /root/tmux.conf capture-pane -e -p -t t")
    run.vm("pkill -x pktgen; true", check=False)
    t.stop()
    run.vm(CLEAN + "; echo '10.99.0.1 gw.test' >> /etc/hosts")
    open(os.path.join(HERE, "vm", "screenshot.ansi"), "w").write(ansi)
    return ansi


if __name__ == "__main__":
    if os.environ.get("RENDER_ONLY"):
        ansi = open(os.path.join(HERE, "vm", "screenshot.ansi")).read()
    else:
        ansi = capture()
    img = diagonal(render(ansi, "light"), render(ansi, "dark"))
    img.save(OUT, optimize=True)
    print(OUT, img.size)

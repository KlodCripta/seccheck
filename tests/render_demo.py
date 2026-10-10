"""Render real PTY demo output for README review. Requires Pillow; not a scan/test."""
import argparse
import fcntl
import os
import pathlib
import pty
import re
import select
import struct
import subprocess
import termios

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--screen', choices=('demo', 'menu'), default='demo')
args = parser.parse_args()
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 80, 88, 0, 0))
attributes = termios.tcgetattr(slave)
attributes[3] &= ~termios.ECHO
termios.tcsetattr(slave, termios.TCSANOW, attributes)
env = dict(os.environ, TERM='xterm-256color', COLORTERM='truecolor', LANG='C.UTF-8')
env.pop('NO_COLOR', None)
command = ['bash', str(ROOT / 'seccheck.sh'), '--lang', 'it', '--demo', 'review']
if args.screen == 'menu':
    # Render the real menu without host probes, scanner calls or installation.
    command = ['bash', '-c', 'source "$1"; sc_parse_args --lang it; sc_ui_init; sc_menu',
               'preview', str(ROOT / 'seccheck.sh')]
process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, env=env)
os.close(slave)
if args.screen == 'menu':
    os.write(master, b'0\n')
data = b''
while True:
    if select.select([master], [], [], 2)[0]:
        try:
            block = os.read(master, 65536)
        except OSError:
            break
        if not block:
            break
        data += block
    elif process.poll() is not None:
        break
process.wait(timeout=5)
os.close(master)
assert process.returncode == 0
lines = data.decode().replace('\r', '').splitlines()
font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 17)
bold = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf', 17)
italic = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Oblique.ttf', 17)
bold_italic = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono-BoldOblique.ttf', 17)
cell = font.getlength('M')
canvas = Image.new('RGB', (int(cell*90+40), len(lines)*24+66), '#111418')
draw = ImageDraw.Draw(canvas)
draw.rounded_rectangle((12, 12, canvas.width-12, 47), radius=8, fill='#25282c')
draw.text((30, 20), 'SecCheck 2.0  |  ' + args.screen.title() + '  |  Terminale 88 colonne', font=font, fill='#eeeeee')
palette = {203:'#ff5f5f', 208:'#ff8700', 114:'#87d787', 255:'#eeeeee'}
color = '#eeeeee'
is_bold = is_italic = is_dim = False
for row, line in enumerate(lines):
    x = 20
    for part in re.split(r'(\x1b\[[0-9;]*m)', line):
        if part.startswith('\x1b['):
            codes = [int(x) for x in part[2:-1].split(';') if x] or [0]
            if codes == [0]:
                color = '#eeeeee'
                is_bold = is_italic = is_dim = False
            elif codes == [1]: is_bold = True
            elif codes == [2]: is_dim = True
            elif codes == [3]: is_italic = True
            elif codes[:2] == [38, 5]: color = palette[codes[2]]
            elif codes[:2] == [38, 2]: color = tuple(codes[2:5])
        else:
            weight = (bold_italic if is_bold else italic) if is_italic else (bold if is_bold else font)
            fill = '#bbbbbb' if is_dim and color == '#eeeeee' else color
            draw.text((x, 58+row*24), part, font=weight, fill=fill)
            x += font.getlength(part)
filename = 'seccheck-v2-result.png' if args.screen == 'demo' else 'seccheck-v2-menu.png'
canvas.save(ROOT / 'screenshots' / filename)

"""Render real PTY demo output for README review. Requires Pillow; not a scan/test."""
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
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 80, 88, 0, 0))
env = dict(os.environ, TERM='xterm-256color', COLORTERM='truecolor', LANG='C.UTF-8')
env.pop('NO_COLOR', None)
process = subprocess.Popen(['bash', str(ROOT / 'seccheck.sh'), '--lang', 'it', '--demo', 'review'],
                           stdin=slave, stdout=slave, stderr=slave, env=env)
os.close(slave)
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
end = next(i for i, line in enumerate(lines) if 'DETTAGLI DELLE SEGNALAZIONI' in line)
lines = lines[:end-1]
font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 17)
bold = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf', 17)
cell = font.getlength('M')
canvas = Image.new('RGB', (int(cell*90+40), len(lines)*24+66), '#0d2028')
draw = ImageDraw.Draw(canvas)
draw.rounded_rectangle((12, 12, canvas.width-12, 47), radius=8, fill='#183642')
draw.text((30, 20), 'SecCheck 2.0  |  Demo  |  Terminale 88 colonne', font=font, fill='#8ca8b9')
palette = {80:'#7acdd8', 109:'#8ca8b9', 203:'#ff5f5f', 222:'#ffdf87', 114:'#87d787'}
color = '#e6edf0'
weight = font
for row, line in enumerate(lines):
    x = 20
    for part in re.split(r'(\x1b\[[0-9;]*m)', line):
        if part.startswith('\x1b['):
            codes = [int(x) for x in part[2:-1].split(';') if x] or [0]
            if codes == [0]: color, weight = '#e6edf0', font
            elif codes == [1]: weight = bold
            elif codes[:2] == [38, 5]: color = palette[codes[2]]
            elif codes[:2] == [38, 2]: color = tuple(codes[2:5])
        else:
            draw.text((x, 58+row*24), part, font=weight, fill=color)
            x += font.getlength(part)
canvas.save(ROOT / 'screenshots' / 'seccheck-v2-petrolio.png')

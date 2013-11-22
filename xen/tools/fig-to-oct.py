#!/usr/bin/env python
import sys

chars_per_line = 18
chars_so_far = 0

sys.stdout.write('"')

for char in sys.stdin.read():

    sys.stdout.write("\\%03o" % ord(char))
    chars_so_far = chars_so_far + 1

    if chars_so_far == chars_per_line:
        chars_so_far = 0
        sys.stdout.write('" \\\n"')

sys.stdout.write('"\n')

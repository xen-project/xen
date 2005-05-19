#!/bin/sh

# QEMU keysym adapter: create a header file to link the name to its keysym
#
# Copyright (c) 2004,2005 Johannes E. Schindelin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

type="$1"
cflags="$2"
if [ -z "$cflags" ]; then
	echo "Usage: $0 vnc|sdl cflags"
	exit 1
fi


case "$type" in
vnc)
	ignore_case=''
	header=rfb/keysym.h
	keysym_t=rfbKeySym
	pattern='^#define[ 	]*XK_\([^ 	]*\)[ 	].*$'
	replacement='#ifdef XK_\1\n{\"\1\", XK_\1},\n#endif'
	extra_replace='cat'
	extra_sort='cat'
	;;
sdl)
	ignore_case='-f'
	header=SDL_keysym.h
	keysym_t=int
	pattern='^[ 	]*SDLK_\([^ 	]*\)[ 	]*=.*$'
	replacement='{\"\1\", SDLK_\1},'
	extra_replace='sed -e s/{"\([RL]\)\(SUPER\|META\|ALT\|CONTROL\|SHIFT\)/{"\2_\1/ -e s/{"\([RL]\)CTRL/{"CONTROL_\1/ -e s/{"\(PAGE\)\(UP\|DOWN\)/{"\1_\2/ -e s/{"\(KP\)\([0-9]\)/{"\1_\2/ -e s/{"KP_MINUS/{"KP_SUBTRACT/ -e s/{"KP_PLUS/{"KP_ADD/ -e s/{"KP_PERIOD/{"KP_DECIMAL/ -e s/{"\(LEFT\|RIGHT\)\(PAREN\|BRACKET\)/{"\2\1/ -e s/{"EXCLAIM/{"EXCLAM/ -e s/{"\(CAPS\|NUM\)\(LOCK\)/{"\1_\2/ -e s/{"SCROLLOCK/{"SCROLL_LOCK/ -e s/{"KP_EQUALS/{"KP_EQUAL/ -e s/{"SYSREQ/{"SYS_REQ/ -e s/{"QUOTE"/{"APOSTROPHE"/ -e s/{"BACKQUOTE/{"GRAVE/ -e s/{"EQUALS/{"EQUAL/ -e s/{"EURO/{"EUROSIGN/ -e s/{"COMPOSE/{"MULTI_KEY/ -e s/{"MODE/{"MODE_SWITCH/ -e s/{"HASH/{"NUMBERSIGN/ -e s/{"WORLD_68/{"ADIAERESIS/ -e s/{"WORLD_86/{"ODIAERESIS/ -e s/{"WORLD_92/{"UDIAERESIS/ -e s/{"WORLD_63/{"SSHARP/ -e s/{"WORLD_20/{"ACUTE/ -e s/{"CARET/{"ASCIICIRCUM/'
	extra_sort='sort -f'
	;;
*) echo "Unknown type: $type is neither vnc nor sdl"; exit 1;;
esac

outfile=keysym_adapter_"$type".h

echo "typedef struct {" > $outfile
echo "	const char* name;" >> $outfile
echo "	$keysym_t keysym;" >> $outfile
echo "} name2keysym_t;" >> $outfile
echo "static name2keysym_t name2keysym[]={" >> $outfile

for path in $(echo "$cflags" | sed "s/-I/ /g"); do
	if [ -f $path/$header ]; then
		cat $path/$header
	fi
done | tr "\011" " " | LC_ALL=C sort $ignore_case | uniq | \
sed -n -e "s/$pattern/$replacement/p" | $extra_replace | \
LC_ALL=C $extra_sort >> $outfile

echo "{0,0}};" >> $outfile

if [ -n "$ignore_case" ]; then
echo "#define KEYBOARD_IGNORE_CASE" >> $outfile
fi



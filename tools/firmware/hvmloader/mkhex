#!/bin/sh

#
# mkhex: Generate C embeddable hexdumps
#
# Leendert van Doorn, leendert@watson.ibm.com
# Copyright (c) 2005, International Business Machines Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA 02111-1307 USA.
#

echo "unsigned $1[] = {"
od -v -t x $2 | sed 's/^[0-9]*  */0x/' | sed 's/  */, 0x/g' | sed 's/$/,/' | sed 's/0x,//' | sed 's/^[0-9]*,//'
echo "};"


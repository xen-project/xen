#
# Copyright (c) 2006, XenSource Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
#

CFLAGS = -Iinclude                     \
         $(shell xml2-config --cflags) \
         $(shell curl-config --cflags) \
         -W -Wall -Werror -std=c99 -O2 -fPIC

LDFLAGS = $(shell xml2-config --libs) \
          $(shell curl-config --libs)

test/test_bindings: test/test_bindings.o src/libxen.so
	$(CC) $(LDFLAGS) -o $@ $< -L src -lxen

src/libxen.so: $(patsubst %.c, %.o, $(wildcard src/*.c))
	$(CC) -shared -o $@ $^

.PHONY: clean
clean:
	rm -f `find -name *.o`
	rm -f src/libxen.so
	rm -f test/test_bindings

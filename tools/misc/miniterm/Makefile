CC      = gcc
CFLAGS  = -O3 -march=i686 -Wall

all: miniterm

install: all
	cp -a miniterm /usr/bin/	

dist: all
	cp -a miniterm ../../../../install/bin/	

clean:
	rm -f *.o miniterm *~

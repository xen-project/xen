# foo.
TEST_SRCS:=$(shell find cases/ -name \*.t | sort -n -t/ -k2)
PROGS:=$(patsubst %.t,%.p,$(TEST_SRCS))
HARNESS_SRCS:=main.c
# io_queue.c

CFLAGS=-Wall -Werror -g -O -laio
#-lpthread -lrt

all: $(PROGS)

$(PROGS): %.p: %.t $(HARNESS_SRCS)
	$(CC) $(CFLAGS) -DTEST_NAME=\"$<\" -o $@ main.c

clean:
	rm -f $(PROGS) *.o runtests.out rofile wofile rwfile

.PHONY:

testdir/rofile: .PHONY
	rm -f $@
	echo "test" >$@
	chmod 400 $@

testdir/wofile: .PHONY
	rm -f $@
	echo "test" >$@
	chmod 200 $@

testdir/rwfile: .PHONY
	rm -f $@
	echo "test" >$@
	chmod 600 $@

check: $(PROGS) testdir/rofile testdir/rwfile testdir/wofile
	./runtests.sh $(PROGS)



CFLAGS += -Wall -Werror -g
LDFLAGS += -g

libgnbd.a: libgnbd.o
	$(AR) r $@ $<

gnbdtest: gnbdtest.o libgnbd.a

XEN_ROOT = ../..

include $(XEN_ROOT)/Config.mk

all: main.a

main-c.c:
	ln -sf $(XEN_ROOT)/extras/mini-os/main.c $@

main.a: main-c.o main.o 
	$(AR) cr $@ $^

clean:
	rm -f *.a *.o

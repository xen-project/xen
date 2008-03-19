XEN_ROOT = ../..

include $(XEN_ROOT)/Config.mk

main.a: main.o
	$(AR) cr $@ $^

clean:
	rm -f *.a *.o

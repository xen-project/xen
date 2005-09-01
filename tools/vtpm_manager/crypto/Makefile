XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

BIN		= libtcpaCrypto.a

all: build

build: $(BIN)

install: build

clean:
	rm -f *.a *.so *.o *.rpm $(DEP_FILES)

mrproper: clean

$(BIN): $(OBJS)
	$(AR) rcs $(BIN) $(OBJS)

XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

BIN		= libTCGUtils.a

all: build

build: $(BIN)

install: build

clean:
	rm -f *.a *.so *.o *.rpm $(DEP_FILES)

mrproper: clean
	rm -f *~

$(BIN): $(OBJS)
	$(AR) rcs $(BIN) $(OBJS)

XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

BIN		= libTCGUtils.a

.PHONY: all
all: build

.PHONY: build
build: $(BIN)

.PHONY: install
install: build

.PHONY: clean
clean:
	rm -f *.a *.so *.o *.rpm $(DEP_FILES)

.PHONY: mrproper
mrproper: clean
	rm -f *~

$(BIN): $(OBJS)
	$(AR) rcs $(BIN) $(OBJS)

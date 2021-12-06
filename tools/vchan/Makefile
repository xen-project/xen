#
# tools/vchan/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

NODE_OBJS = node.o
NODE2_OBJS = node-select.o

$(NODE_OBJS) $(NODE2_OBJS): CFLAGS += $(CFLAGS_libxenvchan) $(CFLAGS_libxengnttab) $(CFLAGS_libxenevtchn)
vchan-socket-proxy.o: CFLAGS += $(CFLAGS_libxenvchan) $(CFLAGS_libxenstore) $(CFLAGS_libxenctrl) $(CFLAGS_libxengnttab) $(CFLAGS_libxenevtchn)

TARGETS := vchan-node1 vchan-node2 vchan-socket-proxy

.PHONY: all
all: $(TARGETS)

vchan-node1: $(NODE_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(NODE_OBJS) $(LDLIBS_libxenvchan) $(APPEND_LDFLAGS)

vchan-node2: $(NODE2_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(NODE2_OBJS) $(LDLIBS_libxenvchan) $(APPEND_LDFLAGS)

vchan-socket-proxy: vchan-socket-proxy.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS_libxenvchan) $(LDLIBS_libxenstore) $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
	$(INSTALL_PROG) vchan-socket-proxy $(DESTDIR)$(bindir)

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

distclean: clean

-include $(DEPS_INCLUDE)

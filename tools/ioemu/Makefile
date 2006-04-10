XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

-include config-host.mak

CFLAGS+=-g -fno-strict-aliasing 
ifdef CONFIG_DARWIN
CFLAGS+= -mdynamic-no-pic
endif
ifdef CONFIG_WIN32
CFLAGS+=-fpack-struct 
endif
LDFLAGS=-g
LIBS=
DEFINES+=-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
TOOLS=qemu-img
ifdef CONFIG_STATIC
LDFLAGS+=-static
endif
#DOCS=qemu-doc.html qemu-tech.html qemu.1

.PHONY: all
all: $(DOCS) HEADERS
	for d in $(TARGET_DIRS); do \
	$(MAKE) -C $$d $@ || exit 1 ; \
        done

qemu-img: qemu-img.c block.c block-cow.c block-qcow.c aes.c block-vmdk.c block-cloop.c
	$(CC) -DQEMU_TOOL $(CFLAGS) $(LDFLAGS) $(DEFINES) -o $@ $^ -lz $(LIBS)

dyngen$(EXESUF): dyngen.c
	$(HOST_CC) $(CFLAGS) $(DEFINES) -o $@ $^

.PHONY: clean
clean:
# avoid old build problems by removing potentially incorrect old files
	rm -f config.mak config.h op-i386.h opc-i386.h gen-op-i386.h op-arm.h opc-arm.h gen-op-arm.h 
	rm -f *.o *.a $(TOOLS) dyngen$(EXESUF) TAGS qemu.pod *~ */*~
	#$(MAKE) -C tests clean
	for d in $(TARGET_DIRS); do \
	$(MAKE) -C $$d $@ || exit 1 ; \
        done
	rm -f config-host.mak config-host.h
	rm -f keysym_adapter_sdl.h keysym_adapter_vnc.h

.PHONY: distclean
distclean: clean
	rm -f config-host.mak config-host.h
	rm -f keysym_adapter_sdl.h keysym_adapter_vnc.h
	for d in $(TARGET_DIRS); do \
	$(MAKE) -C $$d $@ || exit 1 ; \
        done

KEYMAPS=da     en-gb  et  fr     fr-ch  is  lt  modifiers  no  pt-br  sv \
ar      de     en-us  fi  fr-be  hr     it  lv  nl         pl  ru     th \
common  de-ch  es     fo  fr-ca  hu     ja  mk  nl-be      pt  sl     tr

.PHONY: install
install: all 
	mkdir -p "$(bindir)"
	mkdir -p "$(DESTDIR)/$(datadir)"
	mkdir -p "$(DESTDIR)/$(datadir)/keymaps"
	install -m 644 $(addprefix keymaps/,$(KEYMAPS)) "$(DESTDIR)/$(datadir)/keymaps"
	for d in $(TARGET_DIRS); do \
	$(MAKE) -C $$d $@ || exit 1 ; \
        done

# various test targets
.PHONY: test speed test2
test speed test2: all
	$(MAKE) -C tests $@

.PHONY: TAGS
TAGS: 
	etags *.[ch] tests/*.[ch]

# documentation
%.html: %.texi
	texi2html -monolithic -number $<

qemu.1: qemu-doc.texi
	./texi2pod.pl $< qemu.pod
	pod2man --section=1 --center=" " --release=" " qemu.pod > $@

FILE=qemu-$(shell cat VERSION)

# tar release (use 'make -k tar' on a checkouted tree)
.PHONY: tar
tar:
	rm -rf /tmp/$(FILE)
	cp -r . /tmp/$(FILE)
	( cd /tmp ; tar zcvf ~/$(FILE).tar.gz $(FILE) --exclude CVS )
	rm -rf /tmp/$(FILE)

# generate a binary distribution
.PHONY: tarbin
tarbin:
	( cd $(DESTDIR) ; tar zcvf ~/qemu-$(VERSION)-i386.tar.gz \
	$(DESTDIR)/$(bindir)/qemu $(DESTDIR)/$(bindir)/qemu-fast \
	$(DESTDIR)/$(bindir)/qemu-system-ppc \
	$(DESTDIR)/$(bindir)/qemu-i386 \
        $(DESTDIR)/$(bindir)/qemu-arm \
        $(DESTDIR)/$(bindir)/qemu-sparc \
        $(DESTDIR)/$(bindir)/qemu-ppc \
	$(DESTDIR)/$(mandir)/man1/qemu.1 $(DESTDIR)/$(mandir)/man1/qemu-mkcow.1 )

ifneq ($(wildcard .depend),)
include .depend
endif

.PHONY: HEADERS
HEADERS:

ifdef CONFIG_SDL
HEADERS: keysym_adapter_sdl.h
endif

ifdef CONFIG_VNC
HEADERS: keysym_adapter_vnc.h
endif

keysym_adapter_sdl.h: Makefile create_keysym_header.sh
	sh create_keysym_header.sh sdl "$(SDL_CFLAGS)"

keysym_adapter_vnc.h: Makefile create_keysym_header.sh
	sh create_keysym_header.sh vnc "$(VNC_CFLAGS)"



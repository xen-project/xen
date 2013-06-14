obj-bin-y := libelf.o

SECTIONS := text data $(SPECIAL_DATA_SECTIONS)

CFLAGS += -Wno-pointer-sign

libelf.o: libelf-temp.o Makefile
	$(OBJCOPY) $(foreach s,$(SECTIONS),--rename-section .$(s)=.init.$(s)) $< $@

libelf-temp.o: libelf-tools.o libelf-loader.o libelf-dominfo.o #libelf-relocate.o
	$(LD) $(LDFLAGS) -r -o $@ $^

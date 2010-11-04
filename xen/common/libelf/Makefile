obj-y := libelf.o

SECTIONS := text data rodata $(foreach n,1 2 4 8,rodata.str1.$(n)) $(foreach r,rel rel.ro,data.$(r) data.$(r).local)

libelf.o: libelf-temp.o Makefile
	$(OBJCOPY) $(foreach s,$(SECTIONS),--rename-section .$(s)=.init.$(s)) $< $@

libelf-temp.o: libelf-tools.o libelf-loader.o libelf-dominfo.o #libelf-relocate.o
	$(LD) $(LDFLAGS) -r -o $@ $^

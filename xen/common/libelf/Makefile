obj-bin-y := libelf.o
nocov-y += libelf.o
libelf-objs := libelf-tools.o libelf-loader.o libelf-dominfo.o

SECTIONS := text data $(SPECIAL_DATA_SECTIONS)
OBJCOPYFLAGS := $(foreach s,$(SECTIONS),--rename-section .$(s)=.init.$(s))

CFLAGS-y += -Wno-pointer-sign

libelf.o: libelf-temp.o FORCE
	$(call if_changed,objcopy)

libelf-temp.o: $(libelf-objs) FORCE
	$(call if_changed,ld)

extra-y += libelf-temp.o $(libelf-objs)

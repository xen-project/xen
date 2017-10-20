obj-y += gcov_base.o gcov.o
obj-$(CONFIG_GCOV_FORMAT_3_4) += gcc_3_4.o
obj-$(CONFIG_GCOV_FORMAT_4_7) += gcc_4_7.o
obj-$(CONFIG_GCOV_FORMAT_4_9) += gcc_4_9.o
obj-$(CONFIG_GCOV_FORMAT_5)   += gcc_5.o
obj-$(CONFIG_GCOV_FORMAT_7)   += gcc_7.o
obj-$(CONFIG_GCOV_FORMAT_AUTODETECT) += $(call cc-ifversion,lt,0x040700, \
						gcc_3_4.o, $(call cc-ifversion,lt,0x040900, \
						gcc_4_7.o, $(call cc-ifversion,lt,0x050000, \
						gcc_4_9.o, $(call cc-ifversion,lt,0x070000, \
						gcc_5.o, gcc_7.o))))

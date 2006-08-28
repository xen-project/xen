ifneq ($(pae),n)
obj-$(x86_32) += common.o g2_on_s3.o g3_on_s3.o
else
obj-$(x86_32) += common.o g2_on_s2.o
endif

obj-$(x86_64) += common.o g4_on_s4.o g3_on_s3.o g2_on_s3.o

guest_levels  = $(subst g,,$(filter g%,$(subst ., ,$(subst _, ,$(1)))))
shadow_levels = $(subst s,,$(filter s%,$(subst ., ,$(subst _, ,$(1)))))
shadow_defns  = -DGUEST_PAGING_LEVELS=$(call guest_levels,$(1)) \
                -DSHADOW_PAGING_LEVELS=$(call shadow_levels,$(1))

g%.o: multi.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(call shadow_defns,$(@F)) -c $< -o $@

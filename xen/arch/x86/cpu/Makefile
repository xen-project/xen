include $(BASEDIR)/Rules.mk

subdirs-y += mcheck
subdirs-y += mtrr

obj-y += amd.o
obj-y += common.o
obj-y += intel.o
obj-y += intel_cacheinfo.o

obj-$(x86_32) += centaur.o
obj-$(x86_32) += cyrix.o
obj-$(x86_32) += rise.o
obj-$(x86_32) += transmeta.o

include $(BASEDIR)/Post.mk

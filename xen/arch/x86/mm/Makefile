obj-y += shadow/
obj-$(CONFIG_HVM) += hap/

obj-$(CONFIG_HVM) += altp2m.o
obj-$(CONFIG_HVM) += guest_walk_2.o guest_walk_3.o guest_walk_4.o
obj-$(CONFIG_SHADOW_PAGING) += guest_walk_4.o
obj-$(CONFIG_MEM_ACCESS) += mem_access.o
obj-$(CONFIG_MEM_PAGING) += mem_paging.o
obj-$(CONFIG_MEM_SHARING) += mem_sharing.o
obj-y += p2m.o
obj-$(CONFIG_HVM) += p2m-ept.o p2m-pod.o p2m-pt.o
obj-y += paging.o
obj-y += physmap.o

obj-$(CONFIG_X86) += x86/

lib-y += bsearch.o
lib-y += ctors.o
lib-y += ctype.o
lib-y += list-sort.o
lib-y += memset.o
lib-y += muldiv64.o
lib-y += parse-size.o
lib-y += rbtree.o
lib-y += sort.o
lib-$(CONFIG_X86) += xxhash32.o
lib-$(CONFIG_X86) += xxhash64.o

lib32-y := divmod.o
lib32-$(CONFIG_64BIT) :=
lib-y += $(lib32-y)

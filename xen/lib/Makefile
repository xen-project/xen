obj-$(CONFIG_X86) += x86/

lib-y += bsearch.o
lib-y += ctors.o
lib-y += ctype.o
lib-y += list-sort.o
lib-y += memchr.o
lib-y += memchr_inv.o
lib-y += memcmp.o
lib-y += memcpy.o
lib-y += memmove.o
lib-y += memset.o
lib-y += muldiv64.o
lib-y += parse-size.o
lib-y += rbtree.o
lib-y += sort.o
lib-y += strcmp.o
lib-y += strlen.o
lib-y += strncmp.o
lib-y += strnlen.o
lib-$(CONFIG_X86) += xxhash32.o
lib-$(CONFIG_X86) += xxhash64.o

lib32-y := divmod.o
lib32-$(CONFIG_64BIT) :=
lib-y += $(lib32-y)

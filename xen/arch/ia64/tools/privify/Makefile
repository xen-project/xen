privify: privify_elf64.o privify.o
	gcc -g privify.o privify_elf64.o -o privify


privify_elf64.o: privify_elf64.c
	gcc -g -D__KERNEL__ -c privify_elf64.c

privify.o: privify.c
	gcc -nostdinc -g -D__KERNEL__ -c privify.c

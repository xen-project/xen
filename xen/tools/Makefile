
all: figlet elf-reloc

figlet:
	$(MAKE) -C figlet

elf-reloc: elf-reloc.c
	gcc -O2 -Wall -o $@ $<

clean:
	rm -f elf-reloc *~ core
	$(MAKE) -C figlet clean

.PHONY: figlet

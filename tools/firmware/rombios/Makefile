BIOS_BUILDS = BIOS-bochs-latest
#BIOS_BUILDS += BIOS-bochs-2-processors
#BIOS_BUILDS += BIOS-bochs-4-processors
#BIOS_BUILDS += BIOS-bochs-8-processors

.PHONY: all
all: bios

.PHONY: bios
bios: biossums ${BIOS_BUILDS}

.PHONY: clean
clean:
	rm -f  *.o *.a *.s rombios.bin _rombios*_.c
	rm -f  as86-sym.txt ld86-sym.txt 
	rm -f  rombios*.txt rombios*.sym usage biossums
	rm -f  BIOS-bochs-*

BIOS-bochs-latest: rombios.c biossums
	gcc -DBX_SMP_PROCESSORS=1 -E -P $< > _rombios_.c
	bcc -o rombios.s -C-c -D__i86__ -0 -S _rombios_.c
	sed -e 's/^\.text//' -e 's/^\.data//' rombios.s > _rombios_.s
	as86 _rombios_.s -b tmp.bin -u- -w- -g -0 -j -O -l rombios.txt
	-perl makesym.perl < rombios.txt > rombios.sym
	mv tmp.bin BIOS-bochs-latest
	./biossums BIOS-bochs-latest
	rm -f _rombios_.s

BIOS-bochs-2-processors: rombios.c biossums
	gcc -DBX_SMP_PROCESSORS=2 -E -P $< > _rombios2_.c
	bcc -o rombios2.s -C-c -D__i86__ -0 -S _rombios2_.c
	sed -e 's/^\.text//' -e 's/^\.data//' rombios2.s > _rombios2_.s
	as86 _rombios2_.s -b tmp2.bin -u- -w- -g -0 -j -O -l rombios2.txt
	-perl makesym.perl < rombios2.txt > rombios2.sym
	mv tmp2.bin BIOS-bochs-2-processors
	./biossums BIOS-bochs-2-processors
	rm -f _rombios2_.s

BIOS-bochs-4-processors: rombios.c biossums
	gcc -DBX_SMP_PROCESSORS=4 -E -P $< > _rombios4_.c
	bcc -o rombios4.s -C-c -D__i86__ -0 -S _rombios4_.c
	sed -e 's/^\.text//' -e 's/^\.data//' rombios4.s > _rombios4_.s
	as86 _rombios4_.s -b tmp4.bin -u- -w- -g -0 -j -O -l rombios4.txt
	-perl makesym.perl < rombios4.txt > rombios4.sym
	mv tmp4.bin BIOS-bochs-4-processors
	./biossums BIOS-bochs-4-processors
	rm -f _rombios4_.s

BIOS-bochs-8-processors: rombios.c biossums
	gcc -DBX_SMP_PROCESSORS=8 -E -P $< > _rombios8_.c
	bcc -o rombios8.s -C-c -D__i86__ -0 -S _rombios8_.c
	sed -e 's/^\.text//' -e 's/^\.data//' rombios8.s > _rombios8_.s
	as86 _rombios8_.s -b tmp8.bin -u- -w- -g -0 -j -O -l rombios8.txt
	-perl makesym.perl < rombios8.txt > rombios8.sym
	mv tmp8.bin BIOS-bochs-8-processors
	./biossums BIOS-bochs-8-processors
	rm -f _rombios8_.s

biossums: biossums.c
	gcc -o biossums biossums.c


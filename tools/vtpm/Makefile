XEN_ROOT = ../..

# Base definitions and rules
include $(XEN_ROOT)/tools/vtpm/Rules.mk

# Dir name for emulator (as dom0 tpm driver)
TPM_EMULATOR_DIR = tpm_emulator
# Dir name for vtpm instance
VTPM_DIR = vtpm

# Emulator tarball name
TPM_EMULATOR_TARFILE = tpm_emulator-0.2b.tar.gz

GMP_HEADER = /usr/include/gmp.h

all: build

build: $(TPM_EMULATOR_DIR) $(VTPM_DIR) build_sub

install: build
	$(MAKE) -C $(TPM_EMULATOR_DIR) $@
	$(MAKE) -C $(VTPM_DIR) $@

clean:
	@if [ -d $(TPM_EMULATOR_DIR) ]; \
		then $(MAKE) -C $(TPM_EMULATOR_DIR) clean; \
	fi
	@if [ -d $(VTPM_DIR) ]; \
		then $(MAKE) -C $(VTPM_DIR) clean; \
	fi

mrproper:
	rm -f $(TPM_EMULATOR_TARFILE)
	rm -rf $(TPM_EMULATOR_DIR)
	rm -rf $(VTPM_DIR)

# Download Swiss emulator
$(TPM_EMULATOR_TARFILE):
	wget http://download.berlios.de/tpm-emulator/$(TPM_EMULATOR_TARFILE)

# Create vtpm and TPM emulator dirs
# apply patches for 1) used as dom0 tpm driver 2) used as vtpm device instance
$(TPM_EMULATOR_DIR): $(TPM_EMULATOR_TARFILE) tpm_emulator.patch tpm_emulator-0.2b-x86_64.patch
	tar -xzf $(TPM_EMULATOR_TARFILE);
	rm -rf $(TPM_EMULATOR_DIR)
	mv tpm_emulator-0.2 $(TPM_EMULATOR_DIR); 
	
	-cd $(TPM_EMULATOR_DIR); \
	patch -p1 < ../tpm_emulator-0.2b-x86_64.patch; \
	patch -p1 <../tpm_emulator.patch

$(VTPM_DIR): $(TPM_EMULATOR_TARFILE) tpm_emulator-0.2b-x86_64.patch vtpm.patch
	tar -xzf $(TPM_EMULATOR_TARFILE);  
	rm -rf $(VTPM_DIR)
	mv tpm_emulator-0.2 $(VTPM_DIR); 

	-cd $(VTPM_DIR); \
	patch -p1 < ../tpm_emulator-0.2b-x86_64.patch; \
	patch -p1 <../vtpm.patch

build_sub:
	@if [ -e $(GMP_HEADER) ]; then \
		$(MAKE) -C $(VTPM_DIR); \
		if [ "$(BUILD_EMULATOR)" = "y" ]; then \
			$(MAKE) -C $(TPM_EMULATOR_DIR); \
		fi \
	else \
		echo "*** Unable to build VTPMs. libgmp could not be found."; \
	fi


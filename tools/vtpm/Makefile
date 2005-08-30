XEN_ROOT = ../..

# Base definitions and rules
include $(XEN_ROOT)/tools/vtpm/Rules.mk

# Dir name for emulator (as dom0 tpm driver)
TPM_EMULATOR_DIR = tpm_emulator-0.2
# Dir name for vtpm instance
VTPM_DIR = vtpm

# Emulator tarball name
TPM_EMULATOR_TARFILE = tpm_emulator-0.2b.tar.gz

all: build

build: $(TPM_EMULATOR_TARFILE) extract patch build_sub

install: build
	$(MAKE) -C $(TPM_EMULATOR_DIR) $@
	$(MAKE) -C $(VTPM_DIR) $@

clean:
	if [ -d $(TPM_EMULATOR_DIR) ]; \
		then $(MAKE) -C $(TPM_EMULATOR_DIR) clean; \
	fi
	if [ -d $(VTPM_DIR) ]; \
		then $(MAKE) -C $(VTPM_DIR) clean; \
	fi
	rm -rf $(TPM_EMULATOR_DIR)
	rm -rf $(VTPM_DIR)

mrproper: clean
	rm -f $(TPM_EMULATOR_TARFILE)

# Download Swiss emulator
$(TPM_EMULATOR_TARFILE):
	wget http://download.berlios.de/tpm-emulator/$(TPM_EMULATOR_TARFILE)

# Create vtpm and TPM emulator dirs
extract: $(TPM_EMULATOR_DIR)/README $(VTPM_DIR)/README

$(TPM_EMULATOR_DIR)/README:
	-rm -rf $(TPM_EMULATOR_DIR)
	tar -xzf $(TPM_EMULATOR_TARFILE)

$(VTPM_DIR)/README:
	-rm -rf $(VTPM_DIR)
	cp -r --preserve $(TPM_EMULATOR_DIR) $(VTPM_DIR)

# apply patches for 1) used as dom0 tpm driver 2) used as vtpm device instance
patch: $(TPM_EMULATOR_DIR)/Makefile $(VTPM_DIR)/Makefile

$(TPM_EMULATOR_DIR)/Makefile: tpm_emulator.patch
	-cd $(TPM_EMULATOR_DIR); \
	patch -p1 <../tpm_emulator.patch

$(VTPM_DIR)/Makefile: vtpm.patch
	-cd $(VTPM_DIR); \
	patch -p1 <../vtpm.patch

build_sub:
	$(MAKE) -C $(TPM_EMULATOR_DIR)
	$(MAKE) -C $(VTPM_DIR)

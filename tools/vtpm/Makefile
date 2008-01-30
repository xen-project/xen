XEN_ROOT = ../..

# Base definitions and rules
include $(XEN_ROOT)/tools/vtpm/Rules.mk

# Dir name for emulator (as dom0 tpm driver)
TPM_EMULATOR_DIR = tpm_emulator
# Dir name for vtpm instance
VTPM_DIR = vtpm
ORIG_DIR = orig

# Emulator tarball name
TPM_EMULATOR_NAME = tpm_emulator-0.4
TPM_EMULATOR_TARFILE = $(TPM_EMULATOR_NAME).tar.gz

GMP_HEADER = /usr/include/gmp.h

.PHONY: all
all: build

.PHONY: build
build: $(VTPM_DIR) $(TPM_EMULATOR_DIR) build_sub

.PHONY: install
install: build
	if [ "$(BUILD_EMULATOR)" = "y" ]; then \
		$(MAKE) -C $(TPM_EMULATOR_DIR) $@ ;\
	fi 
	$(MAKE) -C $(VTPM_DIR) $@

.PHONY: clean
clean:
	@if [ -d $(TPM_EMULATOR_DIR) ]; \
		then $(MAKE) -C $(TPM_EMULATOR_DIR) clean; \
	fi
	@if [ -d $(VTPM_DIR) ]; \
		then $(MAKE) -C $(VTPM_DIR) clean; \
	fi

.PHONY: mrproper
mrproper:
	rm -f $(TPM_EMULATOR_TARFILE) tpm_emulator.patch.old vtpm.patch.old
	rm -rf $(TPM_EMULATOR_DIR) $(VTPM_DIR) $(ORIG_DIR)

# Download Swiss emulator
$(TPM_EMULATOR_TARFILE):
	wget http://download.berlios.de/tpm-emulator/$(TPM_EMULATOR_TARFILE)

# Create vtpm and TPM emulator dirs
# apply patches for 1) used as dom0 tpm driver 2) used as vtpm device instance
$(TPM_EMULATOR_DIR): $(TPM_EMULATOR_TARFILE) tpm_emulator.patch 
	set -e; if [ "$(BUILD_EMULATOR)" = "y" ]; then \
		rm -rf $(TPM_EMULATOR_DIR); \
		tar -xzf $(TPM_EMULATOR_TARFILE); \
		mv $(TPM_EMULATOR_NAME) $(TPM_EMULATOR_DIR); \
		cd $(TPM_EMULATOR_DIR); \
		patch -p1 <../tpm_emulator.patch; \
	fi

$(VTPM_DIR): $(TPM_EMULATOR_TARFILE) vtpm.patch
	rm -rf $(VTPM_DIR)
	tar -xzf $(TPM_EMULATOR_TARFILE)
	mv $(TPM_EMULATOR_NAME) $(VTPM_DIR)

	set -e; cd $(VTPM_DIR); \
	patch -p1 < ../tpm_emulator.patch; \
	patch -p1 < ../vtpm.patch

orig: $(TPM_EMULATOR_TARFILE)
	mkdir $(ORIG_DIR);
	set -e; cd $(ORIG_DIR); \
	tar -xzf ../$(TPM_EMULATOR_TARFILE);

updatepatches: clean orig
	set -e; if [ "$(BUILD_EMULATOR)" = "y" ]; then \
		find $(TPM_EMULATOR_DIR) -name "*.orig" -print | xargs rm -f; \
		mv tpm_emulator.patch tpm_emulator.patch.old; \
		diff -uprN orig/$(TPM_EMULATOR_NAME) $(TPM_EMULATOR_DIR) > tpm_emulator.patch || true; \
        fi; 
	find $(VTPM_DIR) -name "*.orig" -print | xargs rm -f; 
	mv vtpm.patch vtpm.patch.old; 
	diff -uprN $(TPM_EMULATOR_DIR) $(VTPM_DIR) > vtpm.patch || true;

.PHONY: build_sub
build_sub:
	set -e; if [ -e $(GMP_HEADER) ]; then \
		$(MAKE) -C $(VTPM_DIR); \
		if [ "$(BUILD_EMULATOR)" = "y" ]; then \
			$(MAKE) -C $(TPM_EMULATOR_DIR); \
		fi \
	else \
		echo "*** Unable to build VTPMs. libgmp could not be found."; \
	fi


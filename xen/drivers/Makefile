
default:
	$(MAKE) -C char
	$(MAKE) -C acpi
	$(MAKE) -C pci
	if [ "$(old_drivers)" == "y" ]; then \
	$(MAKE) -C net ; \
	$(MAKE) -C block ; \
	$(MAKE) -C cdrom ; \
	$(MAKE) -C ide ; \
	$(MAKE) -C scsi ; \
	$(MAKE) -C message/fusion ; \
	fi

clean:
	$(MAKE) -C char clean
	$(MAKE) -C acpi clean
	$(MAKE) -C pci clean
	$(MAKE) -C net clean
	$(MAKE) -C block clean
	$(MAKE) -C cdrom clean
	$(MAKE) -C ide clean
	$(MAKE) -C scsi clean
	$(MAKE) -C message/fusion clean

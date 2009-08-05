
SUBDIRS =

TESTS = 01_block_attach_device_pos.test  \
	02_block_attach_file_device_pos.test \
	04_block_attach_device_repeatedly_pos.test \
	05_block_attach_and_dettach_device_repeatedly_pos.test \
	06_block_attach_baddomain_neg.test \
	07_block_attach_baddevice_neg.test \
	08_block_attach_bad_filedevice_neg.test \
	09_block_attach_and_dettach_device_check_data_pos.test \
	10_block_attach_dettach_multiple_devices.test \
	11_block_attach_shared_dom0.test \
	12_block_attach_shared_domU.test

EXTRA_DIST = $(TESTS)

TESTS_ENVIRONMENT=@TENV@

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log
	rm -f *~

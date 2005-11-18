
SUBDIRS =

TESTS =	01_block-list_pos.test 	\
	02_block-list_attachbd_pos.test \
	03_block-list_anotherbd_pos.test \
	04_block-list_nodb_pos.test \
	05_block-list_nonexist_neg.test \
	06_block-list_checkremove_pos.test

XFAIL_TESTS = 

EXTRA_DIST = $(TESTS) $(XFAIL_TESTS)

TESTS_ENVIRONMENT=@TENV@

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log
	rm -f *~

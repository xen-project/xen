
SUBDIRS =

TESTS =	01_block-destroy_btblock_pos.test 	\
	02_block-destroy_rtblock_pos.test	\
	03_block-destroy_nonexist_neg.test	\
	04_block-destroy_nonattached_neg.test 	\
	05_block-destroy_byname_pos.test 	\
	06_block-destroy_check_list_pos.test

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

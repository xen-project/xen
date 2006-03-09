
SUBDIRS =
TESTS = \
	02_network_local_ping_pos.test		\
	03_network_local_tcp_pos.test		\
	04_network_local_udp_pos.test		\
	05_network_dom0_ping_pos.test		\
	06_network_dom0_tcp_pos.test		\
	07_network_dom0_udp_pos.test		\
	11_network_domU_ping_pos.test		\
	12_network_domU_tcp_pos.test		\
	13_network_domU_udp_pos.test



XFAIL_TESTS = 				\
	02_network_local_ping_pos.test		\
	05_network_dom0_ping_pos.test		\
	11_network_domU_ping_pos.test

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

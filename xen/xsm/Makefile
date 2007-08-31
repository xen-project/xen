obj-y += xsm_core.o
obj-y += xsm_policy.o
ifeq ($(XSM_ENABLE),y)
obj-y += dummy.o
endif

subdir-$(FLASK_ENABLE) += flask
subdir-$(ACM_SECURITY) += acm

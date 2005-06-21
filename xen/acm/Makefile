
include $(BASEDIR)/Rules.mk
OBJS =  acm_core.o 
OBJS += acm_policy.o
OBJS += acm_simple_type_enforcement_hooks.o
OBJS += acm_chinesewall_hooks.o
OBJS += acm_null_hooks.o

default: acm.o

acm.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o acm.o $(OBJS)

clean:
	rm -f *.o *~ core

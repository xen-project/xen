LDFLAGS  += -g
CXXFLAGS += -g  -I../../../tools/libxc -I../../../xen/include/public
clean:
	$(RM) -f *.o *~ lib*.a device-model

install::
	

CXXFLAGS += -O2  -I../../../tools/libxc -I../../../xen/include/public
clean:
	$(RM) -f *.o *~ lib*.a device-model

install::
	

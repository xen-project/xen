# head.o is built by descending into arch/arm/$(TARGET_SUBARCH), depends on the
# part of $(ALL_OBJS) that will eventually recurse into $(TARGET_SUBARCH)/ and
# build head.o
arch/arm/$(TARGET_SUBARCH)/head.o: arch/arm/built_in.o ;

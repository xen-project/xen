CC = gcc
TARGET=balloon

$(TARGET): balloon.c
	$(CC) -O2 -Wall -o $(TARGET) balloon.c

install: $(TARGET)
	mkdir -p $(prefix)/usr/bin
	cp -a $(TARGET) $(prefix)/usr/bin

dist: $(TARGET)
	mkdir -p ../../../install/bin
	cp -a $(TARGET) ../../../install/bin

clean:
	$(RM) *.o $(TARGET) *~


CC = gcc
TARGET=balloon

$(TARGET): balloon.c
	$(CC) -O2 -Wall -o $(TARGET) balloon.c

install: $(TARGET)
	mkdir -p /usr/bin
	cp -a $(TARGET) /usr/bin

dist: $(TARGET)
	mkdir -p ../../../install/bin
	cp -a $(TARGET) ../../../install/bin

clean:
	$(RM) *.o $(TARGET) *~


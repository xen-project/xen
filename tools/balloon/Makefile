CC = gcc
TARGET=balloon

$(TARGET): balloon.c
	$(CC) -O2 -Wall -o $(TARGET) balloon.c

install: $(TARGET)
	cp  $(TARGET) ../../../install/bin

clean:
	$(RM) *.o $(TARGET) *~



CC     = gcc
CFLAGS = -Wall -O3
TARGET = miniterm

all: $(TARGET)

install: all
	mkdir -p $(prefix)/usr/bin
	install -m0755 $(TARGET) $(prefix)/usr/bin

clean:
	$(RM) *.o $(TARGET) *~

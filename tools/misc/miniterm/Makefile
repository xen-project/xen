INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

CC     = gcc
CFLAGS = -Wall -O3
TARGET = miniterm

all: $(TARGET)

install: all
	$(INSTALL_DIR) $(prefix)/usr/bin
	$(INSTALL_PROG) $(TARGET) $(prefix)/usr/bin

clean:
	$(RM) *.o $(TARGET) *~

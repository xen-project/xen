CFLAGS+=-Wall -g -Werror

SRCS=main.c cntrl_con.c util.c

all: minixend

#$(SRCS): minixend.h

minixend: $(subst .c,.o,$(SRCS))
	gcc $^ -o $@ $(LDFLAGS) -lxc -lpthread

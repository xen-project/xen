#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "hypervisor-ifs/block.h"

int main(int argc, char *argv[])
{
    xp_disk_t buf;
    int fd;
    char *strbuf;

    if (argc != 5) {
	fprintf(stderr,
		"Usage: xi_physdev_revoke <domain> <device> <start sector> <n_sectors>\n");
	return 1;
    }

    buf.device = atol(argv[2]);
    buf.mode = 0;
    buf.start_sect = atol(argv[3]);
    buf.n_sectors = atol(argv[4]);

    asprintf(&strbuf, "/proc/xeno/dom%s/phd", argv[1]);
    fd = open(strbuf, O_WRONLY);
    if (fd < 0) {
	fprintf(stderr, "Can\'t open %s: %s.\n", strbuf, strerror(errno));
	return 1;
    }
    free(strbuf);

    write(fd, &buf, sizeof(buf));
    close(fd);

    return 0;
}

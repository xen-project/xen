#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/fcntl.h>

#include "physdev.h"

int main(int argc, char *argv[])
{
  xp_disk_t buf;
  int fd;

  if (argc != 5) {
    fprintf(stderr, "Usage: xi_physdev_revoke <domain> <device> <start sector> <n_sectors>\n");
    return 1;
  }

  buf.domain = atol(argv[1]);
  buf.device = atol(argv[2]);
  buf.start_sect = atol(argv[3]);
  buf.n_sectors = atol(argv[4]);

  fd = open("/proc/xeno/dom0/phd", O_WRONLY);
  if (fd < 0) {
    fprintf(stderr, "Can\'t open /proc/xeno/dom0/phd: %s.\n", strerror(errno));
    return 1;
  }

  write(fd, &buf, sizeof(buf));
  close(fd);

  return 0;
}

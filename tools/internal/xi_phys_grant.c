#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/fcntl.h>

#include "physdev.h"

int main(int argc, char *argv[])
{
  xp_disk_t buf;
  int fd;

  if (argc != 6) {
    fprintf(stderr, "Usage: xi_physdev_grant <r/rw> <domain> <device> <start sector> <n_sectors>\n");
    return 1;
  }

  buf.mode = 0;
  if (argv[1][0] == 'r')
    buf.mode |= 1;
  else if (argv[1][0] == 'w')
    buf.mode |= 2;
  if (argv[1][1] == 'r')
    buf.mode |= 1;
  else if (argv[1][1] == 'w')
    buf.mode |= 2;
  
  buf.domain = atol(argv[2]);
  buf.device = atol(argv[3]);
  buf.start_sect = atol(argv[4]);
  buf.n_sectors = atol(argv[5]);

  fd = open("/proc/xeno/dom0/phd", O_WRONLY);
  if (fd < 0) {
    fprintf(stderr, "Can\'t open /proc/xeno/dom0/phd: %s.\n", strerror(errno));
    return 1;
  }

  write(fd, &buf, sizeof(buf));
  close(fd);

  return 0;
}

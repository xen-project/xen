#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/fcntl.h>

#include "physdev.h"

int main(int argc, char *argv[])
{
  xp_disk_t buf;
  int fd;
  char *strbuf;

  if (argc != 7) {
    fprintf(stderr, "Usage: xi_physdev_grant <r/rw> <domain> <device> <start sector> <n_sectors> <partition>\n");
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
  
  buf.device = atol(argv[3]) + atol(argv[6]);
  buf.start_sect = atol(argv[4]);
  buf.n_sectors = atol(argv[5]);

  asprintf(&strbuf, "/proc/xeno/dom%s/phd", argv[2]);
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

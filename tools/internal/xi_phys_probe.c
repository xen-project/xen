#include <stdio.h>
#include <sys/fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "physdev.h"

int main(int argc, char *argv[])
{
  physdisk_probebuf_t buf;
  int fd;
  int x;

  if (argc != 2) {
    fprintf(stderr, "Usage: xi_phys_probe <domain_nr>\n");
    return 1;
  }

  fd = open("/proc/xeno/dom0/phd", O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Can\'t open /proc/xeno/dom0/phd: %s.\n",
	    strerror(errno));
    return 1;
  }

  memset(&buf, 0, sizeof(buf));
  buf.n_aces = PHYSDISK_MAX_ACES_PER_REQUEST;
  while (buf.n_aces == PHYSDISK_MAX_ACES_PER_REQUEST ||
	 buf.n_aces == 0) {
    buf.n_aces = PHYSDISK_MAX_ACES_PER_REQUEST;
    buf.domain = atol(argv[1]);
    read(fd, &buf, sizeof(buf));
    if (!buf.n_aces)
      break;

    printf("Found %d ACEs\n", buf.n_aces);

    for (x = 0; x < buf.n_aces; x++) {
      printf("%x:[%x,%x) : %x\n", buf.entries[x].device,
	     buf.entries[x].start_sect,
	     buf.entries[x].start_sect  + buf.entries[x].n_sectors,
	     buf.entries[x].mode);
    }
    buf.start_ind += buf.n_aces;
  }
  return 0;
}

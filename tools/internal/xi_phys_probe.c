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
  char *strbuf;

  if (argc != 2) {
    fprintf(stderr, "Usage: xi_phys_probe <domain_nr>\n");
    return 1;
  }

  asprintf(&strbuf, "/proc/xeno/dom%s/phd", argv[1]);
  fd = open(strbuf, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Can\'t open %s: %s.\n", strbuf, strerror(errno));
    return 1;
  }
  free(strbuf);

  memset(&buf, 0, sizeof(buf));
  buf.n_aces = PHYSDISK_MAX_ACES_PER_REQUEST;
  do {
    buf.n_aces = PHYSDISK_MAX_ACES_PER_REQUEST;
    read(fd, &buf, sizeof(buf));
    if (!buf.n_aces)
      break;

    for (x = 0; x < buf.n_aces; x++) {
      printf("%x:[%x,%x) : %x\n", buf.entries[x].device,
	     buf.entries[x].start_sect,
	     buf.entries[x].start_sect  + buf.entries[x].n_sectors,
	     buf.entries[x].mode);
    }
    buf.start_ind += buf.n_aces;
  } while (buf.n_aces == PHYSDISK_MAX_ACES_PER_REQUEST);
  return 0;
}

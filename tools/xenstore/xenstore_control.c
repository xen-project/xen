#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xs.h"


int main(int argc, char **argv)
{
  if (argc < 2 ||
      strcmp(argv[1], "check"))
  {
    fprintf(stderr,
            "Usage:\n"
            "\n"
            "       %s check\n"
            "\n", argv[0]);
    return 2;
  }

  struct xs_handle * xsh = xs_daemon_open();

  xs_debug_command(xsh, argv[1], NULL, 0);

  xs_daemon_close(xsh);

  return 0;
}

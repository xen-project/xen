#include <stdio.h>
#include <string.h>

extern int dump_privop_counts (char *buf, int len);

extern int zero_privop_counts (char *buf, int len);

int
main (int argc, char *argv[])
{
  static char buf[8192];
  int res;

  if (argc == 1)
    res = dump_privop_counts (buf, sizeof (buf));
  else if (argc == 2 && strcmp (argv[1], "--clear") == 0)
    res = zero_privop_counts (buf, sizeof (buf));
  else
    {
      printf ("usage: %s [--clear]\n", argv[0]);
      return 1;
    }
  printf ("res=%d\n", res);
  fputs (buf, stdout);

  return 0;
}

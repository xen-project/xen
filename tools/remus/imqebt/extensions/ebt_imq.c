#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include "../include/ebtables_u.h"
#include <linux/netfilter_bridge/ebt_imq.h>

#define IMQ_TODEV '1'

static struct option opts[] =
{
       { "todev"           , required_argument, 0, IMQ_TODEV },
       { 0 }
};

static void help(void)
{
  printf(
    "IMQ options:\n"
    "  --todev <N>         enqueue to imq<N>, defaults to 0\n");
}

static void init(struct ebt_entry_target *target)
{
  struct ebt_imq_info *imqinfo = (struct ebt_imq_info *)target->data;

  imqinfo->todev = 0;
}

static int parse(int c, char **argv, int argc, const struct ebt_u_entry *entry,
   unsigned int *flags, struct ebt_entry_target **target)
{
  struct ebt_imq_info *imqinfo = (struct ebt_imq_info *)(*target)->data;

  switch(c) {
  case IMQ_TODEV:
    imqinfo->todev = atoi(optarg);
  }

  return 1;
}

static void final_check(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target, const char *name,
   unsigned int hookmask, unsigned int time)
{
}

static void print(const struct ebt_u_entry *entry,
   const struct ebt_entry_target *target)
{
  struct ebt_imq_info *imqinfo = (struct ebt_imq_info *)target->data;

  printf("--todev %d", imqinfo->todev);
}

static int compare(const struct ebt_entry_target *t1,
   const struct ebt_entry_target *t2)
{
  struct ebt_imq_info *imqinfo1 = (struct ebt_imq_info *)t1->data;
  struct ebt_imq_info *imqinfo2 = (struct ebt_imq_info *)t2->data;

  if (imqinfo1->todev != imqinfo2->todev)
    return 0;

  return 1;
}

static struct ebt_u_target imq_target =
{
       .name           = "imq",
       .size           = sizeof(struct ebt_imq_info),
       .help           = help,
       .init           = init,
       .parse          = parse,
       .final_check    = final_check,
       .print          = print,
       .compare        = compare,
       .extra_ops      = opts,
};

void _init(void)
{
       ebt_register_target(&imq_target);
}

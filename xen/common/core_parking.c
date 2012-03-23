#include <xen/types.h>

static uint32_t cur_idle_nums;

long core_parking_helper(void *data)
{
    return 0;
}

uint32_t get_cur_idle_nums(void)
{
    return cur_idle_nums;
}

/******************************************************************************
 * dom_mem_ops.h
 *
 * Guest OS operations dealing with physical memory reservations.
 *
 * Copyright (c) 2003, B Dragovic & K A Fraser.
 */

#define MEMOP_RESERVATION_INCREASE 0
#define MEMOP_RESERVATION_DECREASE 1

typedef struct reservation_increase {
    unsigned long   size;
    unsigned long   * pages;
} reservation_increase_t;

typedef struct reservation_decrease {
    unsigned long   size;
    unsigned long   * pages;
} reservation_decrease_t;

typedef struct dom_mem_op
{
    unsigned int op;
    union
    {
        reservation_increase_t increase;
        reservation_decrease_t decrease;
    } u;
} dom_mem_op_t;

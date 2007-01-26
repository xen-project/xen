#ifndef GATEWAY
#define GATEWAY

#include "32bitprotos.h"

void test_gateway();

/* extension for the EBDA */
typedef struct {
  Bit16u reg_ss;
  Bit16u reg_cs;
  Bit16u reg_ds;
  Bit16u reg_es;
  Bit16u esp_hi;
  Bit16u retaddr;
} upcall_t;

#endif

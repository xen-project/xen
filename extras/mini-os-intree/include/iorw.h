#ifndef MINIOS_IORW_H
#define MINIOS_IORW_H

#include <mini-os/types.h>

void iowrite8(volatile void* addr, uint8_t val);
void iowrite16(volatile void* addr, uint16_t val);
void iowrite32(volatile void* addr, uint32_t val);
void iowrite64(volatile void* addr, uint64_t val);

uint8_t ioread8(volatile void* addr);
uint16_t ioread16(volatile void* addr);
uint32_t ioread32(volatile void* addr);
uint64_t ioread64(volatile void* addr);

#endif

#include <mini-os/iorw.h>

void iowrite8(volatile void* addr, uint8_t val)
{
   *((volatile uint8_t*)addr) = val;
}
void iowrite16(volatile void* addr, uint16_t val)
{
   *((volatile uint16_t*)addr) = val;
}
void iowrite32(volatile void* addr, uint32_t val)
{
   *((volatile uint32_t*)addr) = val;
}
void iowrite64(volatile void* addr, uint64_t val)
{
   *((volatile uint64_t*)addr) = val;
}

uint8_t ioread8(volatile void* addr)
{
   return *((volatile uint8_t*) addr);
}
uint16_t ioread16(volatile void* addr)
{
   return *((volatile uint16_t*) addr);
}
uint32_t ioread32(volatile void* addr)
{
   return *((volatile uint32_t*) addr);
}
uint64_t ioread64(volatile void* addr)
{
   return *((volatile uint64_t*) addr);
}

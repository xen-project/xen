#ifndef __HVMLOADER_UTIL_H__
#define __HVMLOADER_UTIL_H__

/* I/O output */
void outw(uint16_t addr, uint16_t val);
void outb(uint16_t addr, uint8_t val);

/* I/O input */
uint8_t inb(uint16_t addr);

/* String and memory functions */
int strcmp(const char *cs, const char *ct);
void *memcpy(void *dest, const void *src, unsigned n);
char *itoa(char *a, unsigned int i);

/* Debug output */
void puts(const char *s);

#endif /* __HVMLOADER_UTIL_H__ */

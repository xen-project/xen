#ifndef __HVMLOADER_UTIL_H__
#define __HVMLOADER_UTIL_H__

/* I/O output */
void outw(uint16_t addr, uint16_t val);
void outb(uint16_t addr, uint8_t val);

/* I/O input */
uint8_t inb(uint16_t addr);

/* Do cpuid instruction, with operation 'idx' */
void cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx,
           uint32_t *ecx, uint32_t *edx);

/* Return number of vcpus. */
int get_vcpu_nr(void);

/* String and memory functions */
int strcmp(const char *cs, const char *ct);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, unsigned n);
unsigned strlen(const char *s);
int memcmp(const void *s1, const void *s2, unsigned n);
void *memcpy(void *dest, const void *src, unsigned n);
void *memset(void *s, int c, unsigned n);
char *itoa(char *a, unsigned int i);

/* Debug output */
void puts(const char *s);

#endif /* __HVMLOADER_UTIL_H__ */

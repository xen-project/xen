#ifndef _ARM_ARM32_BITOPS_H
#define _ARM_ARM32_BITOPS_H

extern void _set_bit(int nr, volatile void * p);
extern void _clear_bit(int nr, volatile void * p);
extern void _change_bit(int nr, volatile void * p);
extern int _test_and_set_bit(int nr, volatile void * p);
extern int _test_and_clear_bit(int nr, volatile void * p);
extern int _test_and_change_bit(int nr, volatile void * p);

#define set_bit(n,p)              _set_bit(n,p)
#define clear_bit(n,p)            _clear_bit(n,p)
#define change_bit(n,p)           _change_bit(n,p)
#define test_and_set_bit(n,p)     _test_and_set_bit(n,p)
#define test_and_clear_bit(n,p)   _test_and_clear_bit(n,p)
#define test_and_change_bit(n,p)  _test_and_change_bit(n,p)

/*
 * Little endian assembly bitops.  nr = 0 -> byte 0 bit 0.
 */
extern int _find_first_zero_bit_le(const void * p, unsigned size);
extern int _find_next_zero_bit_le(const void * p, int size, int offset);
extern int _find_first_bit_le(const unsigned long *p, unsigned size);
extern int _find_next_bit_le(const unsigned long *p, int size, int offset);

/*
 * Big endian assembly bitops.  nr = 0 -> byte 3 bit 0.
 */
extern int _find_first_zero_bit_be(const void * p, unsigned size);
extern int _find_next_zero_bit_be(const void * p, int size, int offset);
extern int _find_first_bit_be(const unsigned long *p, unsigned size);
extern int _find_next_bit_be(const unsigned long *p, int size, int offset);

#ifndef __ARMEB__
/*
 * These are the little endian, atomic definitions.
 */
#define find_first_zero_bit(p,sz)	_find_first_zero_bit_le(p,sz)
#define find_next_zero_bit(p,sz,off)	_find_next_zero_bit_le(p,sz,off)
#define find_first_bit(p,sz)		_find_first_bit_le(p,sz)
#define find_next_bit(p,sz,off)		_find_next_bit_le(p,sz,off)

#else
/*
 * These are the big endian, atomic definitions.
 */
#define find_first_zero_bit(p,sz)	_find_first_zero_bit_be(p,sz)
#define find_next_zero_bit(p,sz,off)	_find_next_zero_bit_be(p,sz,off)
#define find_first_bit(p,sz)		_find_first_bit_be(p,sz)
#define find_next_bit(p,sz,off)		_find_next_bit_be(p,sz,off)

#endif

#endif /* _ARM_ARM32_BITOPS_H */

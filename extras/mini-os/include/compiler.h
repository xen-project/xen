#ifndef __MINIOS_COMPILER_H_
#define __MINIOS_COMPILER_H_

#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif
#define unlikely(x)  __builtin_expect(!!(x),0)
#define likely(x)    __builtin_expect(!!(x),1)

#endif /* __MINIOS_COMPILER_H_ */

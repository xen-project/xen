#ifndef __XEN_TYPESAFE_H__
#define __XEN_TYPESAFE_H__

/*
 * Compiler games to gain type safety between different logical integers.
 *
 * TYPE_SAFE($TYPE, $FOO) declares:
 *  * $FOO_t   which encapsulates $TYPE
 *  * _$FOO()  which boxes a $TYPE as a $FOO_t
 *  * $FOO_x() which unboxes a $FOO_t to $TYPE
 *
 * This makes a $FOO_t and a $BAR_t incompatible even when the box the same
 * $TYPE.
 *
 * It does have some performance cost because the types now have a different
 * storage attribute, so type safety is only enforced in a debug build.
 * Non-debug builds degrade to a simple typedef and noops for the functions.
 */

#ifndef NDEBUG

#define TYPE_SAFE(_type, _name)                                         \
    typedef struct { _type _name; } _name##_t;                          \
    static inline _name##_t _##_name(_type n) { return (_name##_t) { n }; } \
    static inline _type _name##_x(_name##_t n) { return n._name; }

#else

#define TYPE_SAFE(_type, _name)                                         \
    typedef _type _name##_t;                                            \
    static inline _name##_t _##_name(_type n) { return n; }             \
    static inline _type _name##_x(_name##_t n) { return n; }

#endif

#endif /* __XEN_TYPESAFE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

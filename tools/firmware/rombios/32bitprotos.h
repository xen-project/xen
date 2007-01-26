#ifndef PROTOS_HIGHBIOS
#define PROTOS_HIGHBIOS

/* bcc does not like 'enum' */
#define IDX_MULTIPLY   0
#define IDX_ADD        1
#define IDX_SET_STATIC 2
#define IDX_LAST       3 /* keep last! */


#ifdef GCC_PROTOS
  #define PARMS(x...) x
#else
  /* bcc doesn't want any parameter types in prototypes */
  #define PARMS(x...)
#endif

Bit32u multiply( PARMS(Bit32u a, Bit32u b) );
Bit32u add( PARMS(Bit32u a, Bit32u b) );
Bit32u set_static( PARMS(Bit32u) );

#endif

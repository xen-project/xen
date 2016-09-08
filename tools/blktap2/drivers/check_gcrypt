#!/bin/sh

cat > .gcrypt.c << EOF
#include <gcrypt.h>
int main(void) 
{
    gcry_md_hash_buffer(GCRY_MD_MD5, NULL, NULL, 0);
    return 0; 
}
EOF

if $1 -o .gcrypt .gcrypt.c -lgcrypt 2>/dev/null ; then
  echo "yes"
else
  echo "no"
fi

rm -f .gcrypt*

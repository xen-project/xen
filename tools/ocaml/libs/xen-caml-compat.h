/* SPDX-License-Identifier: LGPL-2.1-only WITH OCaml-LGPL-linking-exception */
#ifndef XEN_CAML_COMPAT_H
#define XEN_CAML_COMPAT_H

#ifndef Val_none /* Option handling.  Compat for Ocaml < 4.12 */

#define Val_none Val_int(0)
#define Tag_some 0
#define Some_val(v) Field(v, 0)

static inline value caml_alloc_some(value v)
{
    CAMLparam1(v);

    value some = caml_alloc_small(1, Tag_some);
    Field(some, 0) = v;

    CAMLreturn(some);
}

#endif /* !Val_none */

#endif /* XEN_CAML_COMPAT_H */

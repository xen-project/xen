/*
 * include/xen/atomic.h
 *
 * Common atomic operations entities (atomic_t, function prototypes).
 * Include _from_ arch-side <asm/atomic.h>.
 *
 * Copyright (c) 2016 Bitdefender S.R.L.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __XEN_ATOMIC_H__
#define __XEN_ATOMIC_H__

typedef struct { int counter; } atomic_t;

#define ATOMIC_INIT(i) { (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
static inline int atomic_read(const atomic_t *v);

/**
 * _atomic_read - read atomic variable non-atomically
 * @v atomic_t
 *
 * Non-atomically reads the value of @v
 */
static inline int _atomic_read(atomic_t v);

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void atomic_set(atomic_t *v, int i);

/**
 * _atomic_set - set atomic variable non-atomically
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Non-atomically sets the value of @v to @i.
 */
static inline void _atomic_set(atomic_t *v, int i);

/**
 * atomic_cmpxchg - compare and exchange an atomic variable
 * @v: pointer of type atomic_t
 * @old: old value
 * @new: new value
 *
 * Before calling, @old should be set to @v.
 * Succeeds if @old == @v (likely), in which case stores @new in @v.
 * Returns the initial value in @v, hence succeeds when the return value
 * matches that of @old.
 *
 * Sample (tries atomic increment of v until the operation succeeds):
 *
 *  while(1)
 *  {
 *      int old = atomic_read(&v);
 *      int new = old + 1;
 *      if ( likely(old == atomic_cmpxchg(&v, old, new)) )
 *          break; // success!
 *  }
 */
static inline int atomic_cmpxchg(atomic_t *v, int old, int new);

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic_add(int i, atomic_t *v);

/**
 * atomic_add_return - add integer and return
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline int atomic_add_return(int i, atomic_t *v);

/**
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic_sub(int i, atomic_t *v);

/**
 * atomic_sub_return - sub integer and return
 * @i: integer value to sub
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns @v - @i.
 */
static inline int atomic_sub_return(int i, atomic_t *v);

/**
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic_sub_and_test(int i, atomic_t *v);

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc(atomic_t *v);

/**
 * atomic_inc_return - increment atomic variable and return
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1 and returns @v + 1.
 */
static inline int atomic_inc_return(atomic_t *v);

/**
 * atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic_inc_and_test(atomic_t *v);

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1.
 */
static inline void atomic_dec(atomic_t *v);

/**
 * atomic_dec_return - decrement atomic variable and return
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and returns @v - 1.
 */
static inline int atomic_dec_return(atomic_t *v);

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
static inline int atomic_dec_and_test(atomic_t *v);

/**
 * atomic_add_negative - add and test if negative
 * @v: pointer of type atomic_t
 * @i: integer value to add
 *
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */
static inline int atomic_add_negative(int i, atomic_t *v);

/**
 * atomic_add_unless - add to atomic variable unless it has a specified value
 * @v: pointer of type atomic_t
 * @a: integer value to add
 * @u: integer value @v must -not- be for the add to be performed
 *
 * If @v != @u, adds @a to @v and returns @v + @a.
 * Otherwise returns @u (== @v).
 */
static inline int atomic_add_unless(atomic_t *v, int a, int u);

#endif /* __XEN_ATOMIC_H__ */

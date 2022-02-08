/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 * $FreeBSD$
 */

#ifndef XEN__SYS_QUEUE_H_
#define	XEN__SYS_QUEUE_H_

/* #include <sys/cdefs.h> */

/*
 * This file defines four types of data structures: singly-linked lists,
 * singly-linked tail queues, lists and tail queues.
 *
 * A singly-linked list is headed by a single forward pointer. The elements
 * are singly linked for minimum space and pointer manipulation overhead at
 * the expense of O(n) removal for arbitrary elements. New elements can be
 * added to the list after an existing element or at the head of the list.
 * Elements being removed from the head of the list should use the explicit
 * macro for this purpose for optimum efficiency. A singly-linked list may
 * only be traversed in the forward direction.  Singly-linked lists are ideal
 * for applications with large datasets and few or no removals or for
 * implementing a LIFO queue.
 *
 * A singly-linked tail queue is headed by a pair of pointers, one to the
 * head of the list and the other to the tail of the list. The elements are
 * singly linked for minimum space and pointer manipulation overhead at the
 * expense of O(n) removal for arbitrary elements. New elements can be added
 * to the list after an existing element, at the head of the list, or at the
 * end of the list. Elements being removed from the head of the tail queue
 * should use the explicit macro for this purpose for optimum efficiency.
 * A singly-linked tail queue may only be traversed in the forward direction.
 * Singly-linked tail queues are ideal for applications with large datasets
 * and few or no removals or for implementing a FIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 *
 *
 *				XEN_SLIST	XEN_LIST	XEN_STAILQ	XEN_TAILQ
 * _HEAD			+	+	+	+
 * _HEAD_INITIALIZER		+	+	+	+
 * _ENTRY			+	+	+	+
 * _INIT			+	+	+	+
 * _EMPTY			+	+	+	+
 * _FIRST			+	+	+	+
 * _NEXT			+	+	+	+
 * _PREV			-	-	-	+
 * _LAST			-	-	+	+
 * _FOREACH			+	+	+	+
 * _FOREACH_SAFE		+	+	+	+
 * _FOREACH_REVERSE		-	-	-	+
 * _FOREACH_REVERSE_SAFE	-	-	-	+
 * _INSERT_HEAD			+	+	+	+
 * _INSERT_BEFORE		-	+	-	+
 * _INSERT_AFTER		+	+	+	+
 * _INSERT_TAIL			-	-	+	+
 * _CONCAT			-	-	+	+
 * _REMOVE_AFTER		+	-	+	-
 * _REMOVE_HEAD			+	-	+	-
 * _REMOVE			+	+	+	+
 * _SWAP			+	+	+	+
 *
 */

/*
 * Singly-linked List declarations.
 */
#define	XEN_SLIST_HEAD(name, type)					\
struct name {								\
	type *slh_first;	/* first element */			\
}

#define	XEN_SLIST_HEAD_INITIALIZER(head)				\
	{ 0 }

#define	XEN_SLIST_ENTRY(type)						\
struct {								\
	type *sle_next;	/* next element */				\
}

/*
 * Singly-linked List functions.
 */
#define	XEN_SLIST_EMPTY(head)	((head)->slh_first == 0)

#define	XEN_SLIST_FIRST(head)	((head)->slh_first)

#define	XEN_SLIST_FOREACH(var, head, field)				\
	for ((var) = XEN_SLIST_FIRST((head));				\
	    (var);							\
	    (var) = XEN_SLIST_NEXT((var), field))

#define	XEN_SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = XEN_SLIST_FIRST((head));				\
	    (var) && ((tvar) = XEN_SLIST_NEXT((var), field), 1);	\
	    (var) = (tvar))

#define	XEN_SLIST_FOREACH_PREVPTR(var, varp, head, field)		\
	for ((varp) = &XEN_SLIST_FIRST((head));				\
	    ((var) = *(varp)) != 0;					\
	    (varp) = &XEN_SLIST_NEXT((var), field))

#define	XEN_SLIST_INIT(head) do {					\
	XEN_SLIST_FIRST((head)) = 0;					\
} while (0)

#define	XEN_SLIST_INSERT_AFTER(slistelm, elm, field) do {		\
	XEN_SLIST_NEXT((elm), field) = XEN_SLIST_NEXT((slistelm), field);\
	XEN_SLIST_NEXT((slistelm), field) = (elm);			\
} while (0)

#define	XEN_SLIST_INSERT_HEAD(head, elm, field) do {			\
	XEN_SLIST_NEXT((elm), field) = XEN_SLIST_FIRST((head));		\
	XEN_SLIST_FIRST((head)) = (elm);				\
} while (0)

#define	XEN_SLIST_NEXT(elm, field)	((elm)->field.sle_next)

#define	XEN_SLIST_REMOVE(head, elm, type, field) do {			\
	if (XEN_SLIST_FIRST((head)) == (elm)) {				\
		XEN_SLIST_REMOVE_HEAD((head), field);			\
	}								\
	else {								\
		type *curelm = XEN_SLIST_FIRST((head));			\
		while (XEN_SLIST_NEXT(curelm, field) != (elm))		\
			curelm = XEN_SLIST_NEXT(curelm, field);		\
		XEN_SLIST_REMOVE_AFTER(curelm, field);			\
	}								\
} while (0)

#define XEN_SLIST_REMOVE_AFTER(elm, field) do {				\
	XEN_SLIST_NEXT(elm, field) =					\
	    XEN_SLIST_NEXT(XEN_SLIST_NEXT(elm, field), field);		\
} while (0)

#define	XEN_SLIST_REMOVE_HEAD(head, field) do {				\
	XEN_SLIST_FIRST((head)) = XEN_SLIST_NEXT(XEN_SLIST_FIRST((head)), field);\
} while (0)

#define XEN_SLIST_SWAP(head1, head2, type) do {				\
	type *swap_first = XEN_SLIST_FIRST(head1);			\
	XEN_SLIST_FIRST(head1) = XEN_SLIST_FIRST(head2);		\
	XEN_SLIST_FIRST(head2) = swap_first;				\
} while (0)

/*
 * Singly-linked Tail queue declarations.
 */
#define	XEN_STAILQ_HEAD(name, type)					\
struct name {								\
	type *stqh_first;/* first element */				\
	type **stqh_last;/* addr of last next element */		\
}

#define	XEN_STAILQ_HEAD_INITIALIZER(head)				\
	{ 0, &(head).stqh_first }

#define	XEN_STAILQ_ENTRY(type)						\
struct {								\
	type *stqe_next;	/* next element */			\
}

/*
 * Singly-linked Tail queue functions.
 */
#define	XEN_STAILQ_CONCAT(head1, head2) do {				\
	if (!XEN_STAILQ_EMPTY((head2))) {				\
		*(head1)->stqh_last = (head2)->stqh_first;		\
		(head1)->stqh_last = (head2)->stqh_last;		\
		XEN_STAILQ_INIT((head2));				\
	}								\
} while (0)

#define	XEN_STAILQ_EMPTY(head)	((head)->stqh_first == 0)

#define	XEN_STAILQ_FIRST(head)	((head)->stqh_first)

#define	XEN_STAILQ_FOREACH(var, head, field)				\
	for((var) = XEN_STAILQ_FIRST((head));				\
	   (var);							\
	   (var) = XEN_STAILQ_NEXT((var), field))


#define	XEN_STAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = XEN_STAILQ_FIRST((head));				\
	    (var) && ((tvar) = XEN_STAILQ_NEXT((var), field), 1);	\
	    (var) = (tvar))

#define	XEN_STAILQ_INIT(head) do {					\
	XEN_STAILQ_FIRST((head)) = 0;					\
	(head)->stqh_last = &XEN_STAILQ_FIRST((head));			\
} while (0)

#define	XEN_STAILQ_INSERT_AFTER(head, tqelm, elm, field) do {		\
	if ((XEN_STAILQ_NEXT((elm), field) = XEN_STAILQ_NEXT((tqelm), field)) == 0)\
		(head)->stqh_last = &XEN_STAILQ_NEXT((elm), field);	\
	XEN_STAILQ_NEXT((tqelm), field) = (elm);			\
} while (0)

#define	XEN_STAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((XEN_STAILQ_NEXT((elm), field) = XEN_STAILQ_FIRST((head))) == 0)\
		(head)->stqh_last = &XEN_STAILQ_NEXT((elm), field);	\
	XEN_STAILQ_FIRST((head)) = (elm);				\
} while (0)

#define	XEN_STAILQ_INSERT_TAIL(head, elm, field) do {			\
	XEN_STAILQ_NEXT((elm), field) = 0;				\
	*(head)->stqh_last = (elm);					\
	(head)->stqh_last = &XEN_STAILQ_NEXT((elm), field);		\
} while (0)

#define	XEN_STAILQ_LAST(head, type, field)				\
	(XEN_STAILQ_EMPTY((head)) ?					\
		0 :							\
	        ((type *)(void *)					\
		((char *)((head)->stqh_last) - offsetof(type, field))))

#define	XEN_STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)

#define	XEN_STAILQ_REMOVE(head, elm, type, field) do {			\
	if (XEN_STAILQ_FIRST((head)) == (elm)) {			\
		XEN_STAILQ_REMOVE_HEAD((head), field);			\
	}								\
	else {								\
		type *curelm = XEN_STAILQ_FIRST((head));		\
		while (XEN_STAILQ_NEXT(curelm, field) != (elm))		\
			curelm = XEN_STAILQ_NEXT(curelm, field);	\
		XEN_STAILQ_REMOVE_AFTER(head, curelm, field);		\
	}								\
} while (0)

#define XEN_STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((XEN_STAILQ_NEXT(elm, field) =				\
	     XEN_STAILQ_NEXT(XEN_STAILQ_NEXT(elm, field), field)) == 0)	\
		(head)->stqh_last = &XEN_STAILQ_NEXT((elm), field);	\
} while (0)

#define	XEN_STAILQ_REMOVE_HEAD(head, field) do {			\
	if ((XEN_STAILQ_FIRST((head)) =					\
	     XEN_STAILQ_NEXT(XEN_STAILQ_FIRST((head)), field)) == 0)	\
		(head)->stqh_last = &XEN_STAILQ_FIRST((head));		\
} while (0)

#define XEN_STAILQ_SWAP(head1, head2, type) do {			\
	type *swap_first = XEN_STAILQ_FIRST(head1);			\
	type **swap_last = (head1)->stqh_last;				\
	XEN_STAILQ_FIRST(head1) = XEN_STAILQ_FIRST(head2);		\
	(head1)->stqh_last = (head2)->stqh_last;			\
	XEN_STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (XEN_STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &XEN_STAILQ_FIRST(head1);		\
	if (XEN_STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &XEN_STAILQ_FIRST(head2);		\
} while (0)


/*
 * List declarations.
 */
#define	XEN_LIST_HEAD(name, type)					\
struct name {								\
	type *lh_first;	/* first element */				\
}

#define	XEN_LIST_HEAD_INITIALIZER(head)					\
	{ 0 }

#define	XEN_LIST_ENTRY(type)						\
struct {								\
	type *le_next;	/* next element */				\
	type **le_prev;	/* address of previous next element */		\
}

/*
 * List functions.
 */

#define	XEN_LIST_EMPTY(head)	((head)->lh_first == 0)

#define	XEN_LIST_FIRST(head)	((head)->lh_first)

#define	XEN_LIST_FOREACH(var, head, field)				\
	for ((var) = XEN_LIST_FIRST((head));				\
	    (var);							\
	    (var) = XEN_LIST_NEXT((var), field))

#define	XEN_LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = XEN_LIST_FIRST((head));				\
	    (var) && ((tvar) = XEN_LIST_NEXT((var), field), 1);		\
	    (var) = (tvar))

#define	XEN_LIST_INIT(head) do {					\
	XEN_LIST_FIRST((head)) = 0;					\
} while (0)

#define	XEN_LIST_INSERT_AFTER(listelm, elm, field) do {			\
	if ((XEN_LIST_NEXT((elm), field) = XEN_LIST_NEXT((listelm), field)) != 0)\
		XEN_LIST_NEXT((listelm), field)->field.le_prev =	\
		    &XEN_LIST_NEXT((elm), field);			\
	XEN_LIST_NEXT((listelm), field) = (elm);			\
	(elm)->field.le_prev = &XEN_LIST_NEXT((listelm), field);	\
} while (0)

#define	XEN_LIST_INSERT_BEFORE(listelm, elm, field) do {		\
	(elm)->field.le_prev = (listelm)->field.le_prev;		\
	XEN_LIST_NEXT((elm), field) = (listelm);			\
	*(listelm)->field.le_prev = (elm);				\
	(listelm)->field.le_prev = &XEN_LIST_NEXT((elm), field);	\
} while (0)

#define	XEN_LIST_INSERT_HEAD(head, elm, field) do {			\
	if ((XEN_LIST_NEXT((elm), field) = XEN_LIST_FIRST((head))) != 0)\
		XEN_LIST_FIRST((head))->field.le_prev = &XEN_LIST_NEXT((elm), field);\
	XEN_LIST_FIRST((head)) = (elm);					\
	(elm)->field.le_prev = &XEN_LIST_FIRST((head));			\
} while (0)

#define	XEN_LIST_NEXT(elm, field)	((elm)->field.le_next)

#define	XEN_LIST_REMOVE(elm, field) do {				\
	if (XEN_LIST_NEXT((elm), field) != 0)				\
		XEN_LIST_NEXT((elm), field)->field.le_prev =		\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = XEN_LIST_NEXT((elm), field);		\
} while (0)

#define XEN_LIST_SWAP(head1, head2, type, field) do {			\
	type *swap_tmp = XEN_LIST_FIRST((head1));			\
	XEN_LIST_FIRST((head1)) = XEN_LIST_FIRST((head2));		\
	XEN_LIST_FIRST((head2)) = swap_tmp;				\
	if ((swap_tmp = XEN_LIST_FIRST((head1))) != 0)			\
		swap_tmp->field.le_prev = &XEN_LIST_FIRST((head1));	\
	if ((swap_tmp = XEN_LIST_FIRST((head2))) != 0)			\
		swap_tmp->field.le_prev = &XEN_LIST_FIRST((head2));	\
} while (0)

/*
 * Tail queue declarations.
 */
#define	XEN_TAILQ_HEAD(name, type)					\
struct name {								\
	type *tqh_first;	/* first element */			\
	type **tqh_last;	/* addr of last next element */		\
}

#define	XEN_TAILQ_HEAD_INITIALIZER(head)				\
	{ 0, &(head).tqh_first }

#define	XEN_TAILQ_ENTRY(type)						\
struct {								\
	type *tqe_next;	/* next element */				\
	type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue functions.
 */

#define	XEN_TAILQ_CONCAT(head1, head2, field) do {			\
	if (!XEN_TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		XEN_TAILQ_INIT((head2));				\
	}								\
} while (0)

#define	XEN_TAILQ_EMPTY(head)	((head)->tqh_first == 0)

#define	XEN_TAILQ_FIRST(head)	((head)->tqh_first)

#define	XEN_TAILQ_FOREACH(var, head, field)				\
	for ((var) = XEN_TAILQ_FIRST((head));				\
	    (var);							\
	    (var) = XEN_TAILQ_NEXT((var), field))

#define	XEN_TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = XEN_TAILQ_FIRST((head));				\
	    (var) && ((tvar) = XEN_TAILQ_NEXT((var), field), 1);	\
	    (var) = (tvar))

#define	XEN_TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = XEN_TAILQ_LAST((head), headname);			\
	    (var);							\
	    (var) = XEN_TAILQ_PREV((var), headname, field))

#define	XEN_TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)	\
	for ((var) = XEN_TAILQ_LAST((head), headname);			\
	    (var) && ((tvar) = XEN_TAILQ_PREV((var), headname, field), 1);\
	    (var) = (tvar))

#define	XEN_TAILQ_INIT(head) do {					\
	XEN_TAILQ_FIRST((head)) = 0;					\
	(head)->tqh_last = &XEN_TAILQ_FIRST((head));			\
} while (0)

#define	XEN_TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if ((XEN_TAILQ_NEXT((elm), field) = XEN_TAILQ_NEXT((listelm), field)) != 0)\
		XEN_TAILQ_NEXT((elm), field)->field.tqe_prev =		\
		    &XEN_TAILQ_NEXT((elm), field);			\
	else {								\
		(head)->tqh_last = &XEN_TAILQ_NEXT((elm), field);	\
	}								\
	XEN_TAILQ_NEXT((listelm), field) = (elm);			\
	(elm)->field.tqe_prev = &XEN_TAILQ_NEXT((listelm), field);	\
} while (0)

#define	XEN_TAILQ_INSERT_BEFORE(listelm, elm, field) do {		\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	XEN_TAILQ_NEXT((elm), field) = (listelm);			\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &XEN_TAILQ_NEXT((elm), field);	\
} while (0)

#define	XEN_TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((XEN_TAILQ_NEXT((elm), field) = XEN_TAILQ_FIRST((head))) != 0)\
		XEN_TAILQ_FIRST((head))->field.tqe_prev =		\
		    &XEN_TAILQ_NEXT((elm), field);			\
	else								\
		(head)->tqh_last = &XEN_TAILQ_NEXT((elm), field);	\
	XEN_TAILQ_FIRST((head)) = (elm);				\
	(elm)->field.tqe_prev = &XEN_TAILQ_FIRST((head));		\
} while (0)

#define	XEN_TAILQ_INSERT_TAIL(head, elm, field) do {			\
	XEN_TAILQ_NEXT((elm), field) = 0;				\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &XEN_TAILQ_NEXT((elm), field);		\
} while (0)

#define	XEN_TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

#define	XEN_TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	XEN_TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

#define	XEN_TAILQ_REMOVE(head, elm, field) do {				\
	if ((XEN_TAILQ_NEXT((elm), field)) != 0)			\
		XEN_TAILQ_NEXT((elm), field)->field.tqe_prev =		\
		    (elm)->field.tqe_prev;				\
	else {								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	}								\
	*(elm)->field.tqe_prev = XEN_TAILQ_NEXT((elm), field);		\
} while (0)

#define XEN_TAILQ_SWAP(head1, head2, type, field) do {			\
	type *swap_first = (head1)->tqh_first;				\
	type **swap_last = (head1)->tqh_last;				\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != 0)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != 0)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)

#endif /* !XEN__SYS_QUEUE_H_ */

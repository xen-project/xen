/*
 * list.h
 * 
 * This is a subset of linux's list.h intended to be used in user-space.
 * 
 */

#ifndef __LIST_H__
#define __LIST_H__

#ifdef LIST_HEAD
#undef LIST_HEAD
#endif

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

struct list_head {
        struct list_head *next, *prev;
};
 
#define LIST_HEAD_INIT(name) { &(name), &(name) }
 
#define LIST_HEAD(name) \
        struct list_head name = LIST_HEAD_INIT(name)

static inline void __list_add(struct list_head *new,
                              struct list_head *prev,
                              struct list_head *next)
{
        next->prev = new;
        new->next = next;
        new->prev = prev;
        prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
        __list_add(new, head, head->next);
}
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
        next->prev = prev;
        prev->next = next;
}
static inline void list_del(struct list_head *entry)
{
        __list_del(entry->prev, entry->next);
        entry->next = LIST_POISON1;
        entry->prev = LIST_POISON2;
}
#define list_entry(ptr, type, member)                                   \
        ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))
#define list_for_each_entry(pos, head, member)                          \
        for (pos = list_entry((head)->next, typeof(*pos), member);      \
             &pos->member != (head);                                    \
             pos = list_entry(pos->member.next, typeof(*pos), member))

#endif /* __LIST_H__ */

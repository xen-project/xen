#ifndef _XFRD_SELECT_H_
#define _XFRD_SELECT_H_

/** Set of file descriptors for select.
 */
typedef struct SelectSet {
    int n;
    fd_set rd, wr, er;
} SelectSet;

extern void SelectSet_zero(SelectSet *set);
extern void SelectSet_add_read(SelectSet *set, int fd);
extern void SelectSet_add_write(SelectSet *set, int fd);
extern int SelectSet_select(SelectSet *set, struct timeval *timeout);

#endif /* ! _XFRD_SELECT_H_ */

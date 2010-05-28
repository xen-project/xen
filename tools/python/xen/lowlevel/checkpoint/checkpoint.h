/* API for checkpointing */

#ifndef _CHECKPOINT_H_
#define _CHECKPOINT_H_ 1

#include <pthread.h>
#include <semaphore.h>
#include <time.h>

#include <xenguest.h>
#include <xs.h>

typedef enum {
    dt_unknown,
    dt_pv,
    dt_hvm,
    dt_pvhvm /* HVM with PV drivers */
} checkpoint_domtype;

typedef struct {
    xc_interface *xch;
    int xce;               /* event channel handle */
    struct xs_handle* xsh; /* xenstore handle */
    int watching_shutdown; /* state of watch on @releaseDomain */

    unsigned int domid;
    checkpoint_domtype domtype;
    int fd;

    int suspend_evtchn;

    char* errstr;

    /* suspend deadline thread support */
    volatile int suspended;
    volatile int done;
    pthread_t suspend_thr;
    sem_t suspended_sem;
    sem_t resumed_sem;
    timer_t timer;
} checkpoint_state;

char* checkpoint_error(checkpoint_state* s);

void checkpoint_init(checkpoint_state* s);
int checkpoint_open(checkpoint_state* s, unsigned int domid);
void checkpoint_close(checkpoint_state* s);
int checkpoint_start(checkpoint_state* s, int fd,
                    struct save_callbacks* callbacks);
int checkpoint_suspend(checkpoint_state* s);
int checkpoint_resume(checkpoint_state* s);
int checkpoint_postflush(checkpoint_state* s);

int checkpoint_settimer(checkpoint_state* s, int millis);
int checkpoint_wait(checkpoint_state* s);
void block_timer(void);
void unblock_timer(void);

#endif

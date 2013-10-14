/*
 * FIFO-based event channel ABI.
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2 or later.  See the file COPYING for more details.
 */
#ifndef __XEN_EVENT_FIFO_H__
#define __XEN_EVENT_FIFO_H__

struct evtchn_fifo_queue {
    uint32_t *head; /* points into control block */
    uint32_t tail;
    uint8_t priority;
    spinlock_t lock;
};

struct evtchn_fifo_vcpu {
    struct evtchn_fifo_control_block *control_block;
    struct evtchn_fifo_queue queue[EVTCHN_FIFO_MAX_QUEUES];
};

#define EVTCHN_FIFO_EVENT_WORDS_PER_PAGE (PAGE_SIZE / sizeof(event_word_t))
#define EVTCHN_FIFO_MAX_EVENT_ARRAY_PAGES \
    (EVTCHN_FIFO_NR_CHANNELS / EVTCHN_FIFO_EVENT_WORDS_PER_PAGE)

struct evtchn_fifo_domain {
    event_word_t *event_array[EVTCHN_FIFO_MAX_EVENT_ARRAY_PAGES];
    unsigned int num_evtchns;
};

int evtchn_fifo_init_control(struct evtchn_init_control *init_control);
int evtchn_fifo_expand_array(const struct evtchn_expand_array *expand_array);
void evtchn_fifo_destroy(struct domain *domain);

#endif /* __XEN_EVENT_FIFO_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

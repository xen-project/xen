/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/shutdown.h>

#include <asm/opal-api.h>

int64_t opal_cec_power_down(uint64_t request);
int64_t opal_cec_reboot(void);
int64_t opal_poll_events(uint64_t *outstanding_event_mask);

void machine_halt(void)
{
    int rc;

    /* TODO: mask any OPAL IRQs before shutting down */

    do {
        rc = opal_cec_power_down(0);

        if ( rc == OPAL_BUSY_EVENT )
            opal_poll_events(NULL);

    } while ( rc == OPAL_BUSY || rc == OPAL_BUSY_EVENT );

    for ( ;; )
        opal_poll_events(NULL);
}

void machine_restart(unsigned int delay_millisecs)
{
    int rc;

    /*
     * TODO: mask any OPAL IRQs before shutting down
     * TODO: mdelay(delay_millisecs);
     */

    do {
        rc = opal_cec_reboot();

        if ( rc == OPAL_BUSY_EVENT )
            opal_poll_events(NULL);

    } while ( rc == OPAL_BUSY || rc == OPAL_BUSY_EVENT );

    for ( ;; )
        opal_poll_events(NULL);
}


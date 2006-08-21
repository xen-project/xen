#include <xen/config.h>
#include <xen/types.h>
#include <xen/shadow.h>
#include <public/dom0_ops.h>

int shadow_control_op(struct domain *d, 
                      dom0_shadow_control_t *sc,
                      XEN_GUEST_HANDLE(dom0_op_t) u_dom0_op)
{
    if ( unlikely(d == current->domain) )
    {
        DPRINTK("Don't try to do a shadow op on yourself!\n");
        return -EINVAL;
    }

    switch ( sc->op )
    {
    case DOM0_SHADOW_CONTROL_OP_OFF:
        return 0;

    case DOM0_SHADOW2_CONTROL_OP_GET_ALLOCATION:
        sc->mb = 0;
        return 0;
    case DOM0_SHADOW2_CONTROL_OP_SET_ALLOCATION:
        if (sc->mb > 0) {
            BUG();
            return -ENOMEM;
        }
        return 0;

    default:
        printk("Bad shadow op %u\n", sc->op);
        BUG();
        return -EINVAL;
    }
}

#ifndef __XEN_PIRQ_H
#define __XEN_PIRQ_H

#define PIRQ_BASE       0
#define NR_PIRQS        256

#define DYNIRQ_BASE     (PIRQ_BASE + NR_PIRQS)
#define NR_DYNIRQS      256

#endif /* __XEN_PIRQ_H */


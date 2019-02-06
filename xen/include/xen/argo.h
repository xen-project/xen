/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
 * Copyright (c) 2018, BAE Systems
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __XEN_ARGO_H__
#define __XEN_ARGO_H__

#include <xen/sched.h>

#ifdef CONFIG_ARGO

int argo_init(struct domain *d);
void argo_destroy(struct domain *d);
void argo_soft_reset(struct domain *d);

#else /* !CONFIG_ARGO */

static inline int argo_init(struct domain *d)
{
    return 0;
}

static inline void argo_destroy(struct domain *d)
{
}

static inline void argo_soft_reset(struct domain *d)
{
}

#endif

#endif

/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
 * Derived from v4v, the version 2 of v2v.
 *
 * Copyright (c) 2010, Citrix Systems
 * Copyright (c) 2018-2019 BAE Systems
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

#include <xen/errno.h>
#include <xen/guest_access.h>

long
do_argo_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
           XEN_GUEST_HANDLE_PARAM(void) arg2, unsigned long raw_arg3,
           unsigned long raw_arg4)
{
    return -ENOSYS;
}

#ifdef CONFIG_COMPAT
long
compat_argo_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
               XEN_GUEST_HANDLE_PARAM(void) arg2, unsigned long arg3,
               unsigned long arg4)
{
    return -ENOSYS;
}
#endif

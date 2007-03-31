/******************************************************************************
 * gntdev.c
 * 
 * Device for accessing (in user-space) pages that have been granted by other
 * domains.
 *
 * Copyright (c) 2006-2007, D G Murray.
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

#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <xen/gnttab.h>
#include <asm/hypervisor.h>
#include <xen/balloon.h>
#include <xen/evtchn.h>
#include <xen/driver_util.h>

#include <linux/types.h>
#include <xen/public/gntdev.h>


#define DRIVER_AUTHOR "Derek G. Murray <Derek.Murray@cl.cam.ac.uk>"
#define DRIVER_DESC   "User-space granted page access driver"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

#define MAX_GRANTS 128

/* A slot can be in one of three states:
 *
 * 0. GNTDEV_SLOT_INVALID:
 *    This slot is not associated with a grant reference, and is therefore free
 *    to be overwritten by a new grant reference.
 *
 * 1. GNTDEV_SLOT_NOT_YET_MAPPED:
 *    This slot is associated with a grant reference (via the 
 *    IOCTL_GNTDEV_MAP_GRANT_REF ioctl), but it has not yet been mmap()-ed.
 *
 * 2. GNTDEV_SLOT_MAPPED:
 *    This slot is associated with a grant reference, and has been mmap()-ed.
 */
typedef enum gntdev_slot_state {
	GNTDEV_SLOT_INVALID = 0,
	GNTDEV_SLOT_NOT_YET_MAPPED,
	GNTDEV_SLOT_MAPPED
} gntdev_slot_state_t;

#define GNTDEV_INVALID_HANDLE    -1
#define GNTDEV_FREE_LIST_INVALID -1
/* Each opened instance of gntdev is associated with a list of grants,
 * represented by an array of elements of the following type,
 * gntdev_grant_info_t.
 */
typedef struct gntdev_grant_info {
	gntdev_slot_state_t state;
	union {
		uint32_t free_list_index;
		struct {
			domid_t domid;
			grant_ref_t ref;
			grant_handle_t kernel_handle;
			grant_handle_t user_handle;
			uint64_t dev_bus_addr;
		} valid;
	} u;
} gntdev_grant_info_t;

/* Private data structure, which is stored in the file pointer for files
 * associated with this device.
 */
typedef struct gntdev_file_private_data {
  
	/* Array of grant information. */
	gntdev_grant_info_t grants[MAX_GRANTS];

	/* Read/write semaphore used to protect the grants array. */
	struct rw_semaphore grants_sem;

	/* An array of indices of free slots in the grants array.
	 * N.B. An entry in this list may temporarily have the value
	 * GNTDEV_FREE_LIST_INVALID if the corresponding slot has been removed
	 * from the list by the contiguous allocator, but the list has not yet
	 * been compressed. However, this is not visible across invocations of
	 * the device.
	 */
	int32_t free_list[MAX_GRANTS];
	
	/* The number of free slots in the grants array. */
	uint32_t free_list_size;

	/* Read/write semaphore used to protect the free list. */
	struct rw_semaphore free_list_sem;
	
	/* Index of the next slot after the most recent contiguous allocation, 
	 * for use in a next-fit allocator.
	 */
	uint32_t next_fit_index;

	/* Used to map grants into the kernel, before mapping them into user
	 * space.
	 */
	struct page **foreign_pages;

} gntdev_file_private_data_t;

/* Module lifecycle operations. */
static int __init gntdev_init(void);
static void __exit gntdev_exit(void);

module_init(gntdev_init);
module_exit(gntdev_exit);

/* File operations. */
static int gntdev_open(struct inode *inode, struct file *flip);
static int gntdev_release(struct inode *inode, struct file *flip);
static int gntdev_mmap(struct file *flip, struct vm_area_struct *vma);
static int gntdev_ioctl (struct inode *inode, struct file *flip,
			 unsigned int cmd, unsigned long arg);

static struct file_operations gntdev_fops = {
	.owner = THIS_MODULE,
	.open = gntdev_open,
	.release = gntdev_release,
	.mmap = gntdev_mmap,
	.ioctl = gntdev_ioctl
};

/* VM operations. */
static void gntdev_vma_close(struct vm_area_struct *vma);
static pte_t gntdev_clear_pte(struct vm_area_struct *vma, unsigned long addr,
			      pte_t *ptep, int is_fullmm);

static struct vm_operations_struct gntdev_vmops = {
	.close = gntdev_vma_close,
	.ptep_get_and_clear_full = gntdev_clear_pte
};

/* Global variables. */

/* The driver major number, for use when unregistering the driver. */
static int gntdev_major;

#define GNTDEV_NAME "gntdev"

/* Memory mapping functions
 * ------------------------
 *
 * Every granted page is mapped into both kernel and user space, and the two
 * following functions return the respective virtual addresses of these pages.
 *
 * When shadow paging is disabled, the granted page is mapped directly into
 * user space; when it is enabled, it is mapped into the kernel and remapped
 * into user space using vm_insert_page() (see gntdev_mmap(), below).
 */

/* Returns the virtual address (in user space) of the @page_index'th page
 * in the given VM area.
 */
static inline unsigned long get_user_vaddr (struct vm_area_struct *vma,
					    int page_index)
{
	return (unsigned long) vma->vm_start + (page_index << PAGE_SHIFT);
}

/* Returns the virtual address (in kernel space) of the @slot_index'th page
 * mapped by the gntdev instance that owns the given private data struct.
 */
static inline unsigned long get_kernel_vaddr (gntdev_file_private_data_t *priv,
					      int slot_index)
{
	unsigned long pfn;
	void *kaddr;
	pfn = page_to_pfn(priv->foreign_pages[slot_index]);
	kaddr = pfn_to_kaddr(pfn);
	return (unsigned long) kaddr;
}

/* Helper functions. */

/* Adds information about a grant reference to the list of grants in the file's
 * private data structure. Returns non-zero on failure. On success, sets the
 * value of *offset to the offset that should be mmap()-ed in order to map the
 * grant reference.
 */
static int add_grant_reference(struct file *flip,
			       struct ioctl_gntdev_grant_ref *op,
			       uint64_t *offset)
{
	gntdev_file_private_data_t *private_data 
		= (gntdev_file_private_data_t *) flip->private_data;

	uint32_t slot_index;

	if (unlikely(private_data->free_list_size == 0)) {
		return -ENOMEM;
	}

	slot_index = private_data->free_list[--private_data->free_list_size];

	/* Copy the grant information into file's private data. */
	private_data->grants[slot_index].state = GNTDEV_SLOT_NOT_YET_MAPPED;
	private_data->grants[slot_index].u.valid.domid = op->domid;
	private_data->grants[slot_index].u.valid.ref = op->ref;

	/* The offset is calculated as the index of the chosen entry in the
	 * file's private data's array of grant information. This is then
	 * shifted to give an offset into the virtual "file address space".
	 */
	*offset = slot_index << PAGE_SHIFT;

	return 0;
}

/* Adds the @count grant references to the contiguous range in the slot array
 * beginning at @first_slot. It is assumed that @first_slot was returned by a
 * previous invocation of find_contiguous_free_range(), during the same
 * invocation of the driver.
 */
static int add_grant_references(struct file *flip,
				int count,
				struct ioctl_gntdev_grant_ref *ops,
				uint32_t first_slot)
{
	gntdev_file_private_data_t *private_data 
		= (gntdev_file_private_data_t *) flip->private_data;
	int i;
	
	for (i = 0; i < count; ++i) {

		/* First, mark the slot's entry in the free list as invalid. */
		int free_list_index = 
			private_data->grants[first_slot+i].u.free_list_index;
		private_data->free_list[free_list_index] = 
			GNTDEV_FREE_LIST_INVALID;

		/* Now, update the slot. */
		private_data->grants[first_slot+i].state = 
			GNTDEV_SLOT_NOT_YET_MAPPED;
		private_data->grants[first_slot+i].u.valid.domid =
			ops[i].domid;
		private_data->grants[first_slot+i].u.valid.ref = ops[i].ref;
	}

	return 0;	
}

/* Scans through the free list for @flip, removing entries that are marked as
 * GNTDEV_SLOT_INVALID. This will reduce the recorded size of the free list to
 * the number of valid entries.
 */
static void compress_free_list(struct file *flip) 
{
	gntdev_file_private_data_t *private_data 
		= (gntdev_file_private_data_t *) flip->private_data;
	int i, j = 0, old_size;
	
	old_size = private_data->free_list_size;
	for (i = 0; i < old_size; ++i) {
		if (private_data->free_list[i] != GNTDEV_FREE_LIST_INVALID) {
			private_data->free_list[j] = 
				private_data->free_list[i];
			++j;
		} else {
			--private_data->free_list_size;
		}
	}
}

/* Searches the grant array in the private data of @flip for a range of
 * @num_slots contiguous slots in the GNTDEV_SLOT_INVALID state.
 *
 * Returns the index of the first slot if a range is found, otherwise -ENOMEM.
 */
static int find_contiguous_free_range(struct file *flip,
				      uint32_t num_slots) 
{
	gntdev_file_private_data_t *private_data 
		= (gntdev_file_private_data_t *) flip->private_data;
	
	int i;
	int start_index = private_data->next_fit_index;
	int range_start = 0, range_length;

	if (private_data->free_list_size < num_slots) {
		return -ENOMEM;
	}

	/* First search from the start_index to the end of the array. */
	range_length = 0;
	for (i = start_index; i < MAX_GRANTS; ++i) {
		if (private_data->grants[i].state == GNTDEV_SLOT_INVALID) {
			if (range_length == 0) {
				range_start = i;
			}
			++range_length;
			if (range_length == num_slots) {
				return range_start;
			}
		}
	}
	
	/* Now search from the start of the array to the start_index. */
	range_length = 0;
	for (i = 0; i < start_index; ++i) {
		if (private_data->grants[i].state == GNTDEV_SLOT_INVALID) {
			if (range_length == 0) {
				range_start = i;
			}
			++range_length;
			if (range_length == num_slots) {
				return range_start;
			}
		}
	}
	
	return -ENOMEM;
}

/* Interface functions. */

/* Initialises the driver. Called when the module is loaded. */
static int __init gntdev_init(void)
{
	struct class *class;
	struct class_device *device;

	if (!is_running_on_xen()) {
		printk(KERN_ERR "You must be running Xen to use gntdev\n");
		return -ENODEV;
	}

	gntdev_major = register_chrdev(0, GNTDEV_NAME, &gntdev_fops);
	if (gntdev_major < 0)
	{
		printk(KERN_ERR "Could not register gntdev device\n");
		return -ENOMEM;
	}

	/* Note that if the sysfs code fails, we will still initialise the
	 * device, and output the major number so that the device can be
	 * created manually using mknod.
	 */
	if ((class = get_xen_class()) == NULL) {
		printk(KERN_ERR "Error setting up xen_class\n");
		printk(KERN_ERR "gntdev created with major number = %d\n", 
		       gntdev_major);
		return 0;
	}

	device = class_device_create(class, NULL, MKDEV(gntdev_major, 0),
				     NULL, GNTDEV_NAME);
	if (IS_ERR(device)) {
		printk(KERN_ERR "Error creating gntdev device in xen_class\n");
		printk(KERN_ERR "gntdev created with major number = %d\n",
		       gntdev_major);
		return 0;
	}

	return 0;
}

/* Cleans up and unregisters the driver. Called when the driver is unloaded.
 */
static void __exit gntdev_exit(void)
{
	struct class *class;
	if ((class = get_xen_class()) != NULL)
		class_device_destroy(class, MKDEV(gntdev_major, 0));
	unregister_chrdev(gntdev_major, GNTDEV_NAME);
}

/* Called when the device is opened. */
static int gntdev_open(struct inode *inode, struct file *flip)
{
	gntdev_file_private_data_t *private_data;
	int i;

	try_module_get(THIS_MODULE);

	/* Allocate space for the per-instance private data. */
	private_data = kmalloc(sizeof(*private_data), GFP_KERNEL);
	if (!private_data)
		goto nomem_out;

	/* Allocate space for the kernel-mapping of granted pages. */
	private_data->foreign_pages = 
		alloc_empty_pages_and_pagevec(MAX_GRANTS);
	if (!private_data->foreign_pages)
		goto nomem_out2;

	/* Initialise the free-list, which contains all slots at first.
	 */
	for (i = 0; i < MAX_GRANTS; ++i) {
		private_data->free_list[MAX_GRANTS - i - 1] = i;
		private_data->grants[i].state = GNTDEV_SLOT_INVALID;
		private_data->grants[i].u.free_list_index = MAX_GRANTS - i - 1;
	}
	private_data->free_list_size = MAX_GRANTS;
	private_data->next_fit_index = 0;

	init_rwsem(&private_data->grants_sem);
	init_rwsem(&private_data->free_list_sem);

	flip->private_data = private_data;

	return 0;

nomem_out2:
	kfree(private_data);
nomem_out:
	return -ENOMEM;
}

/* Called when the device is closed.
 */
static int gntdev_release(struct inode *inode, struct file *flip)
{
	if (flip->private_data) {
		gntdev_file_private_data_t *private_data = 
			(gntdev_file_private_data_t *) flip->private_data;
		if (private_data->foreign_pages) {
			free_empty_pages_and_pagevec
				(private_data->foreign_pages, MAX_GRANTS);
		}
		kfree(private_data);
	}
	module_put(THIS_MODULE);
	return 0;
}

/* Called when an attempt is made to mmap() the device. The private data from
 * @flip contains the list of grant references that can be mapped. The vm_pgoff
 * field of @vma contains the index into that list that refers to the grant
 * reference that will be mapped. Only mappings that are a multiple of
 * PAGE_SIZE are handled.
 */
static int gntdev_mmap (struct file *flip, struct vm_area_struct *vma) 
{
	struct gnttab_map_grant_ref op;
	unsigned long slot_index = vma->vm_pgoff;
	unsigned long kernel_vaddr, user_vaddr;
	uint32_t size = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	uint64_t ptep;
	int ret;
	int flags;
	int i;
	struct page *page;
	gntdev_file_private_data_t *private_data = flip->private_data;

	if (unlikely(!private_data)) {
		printk(KERN_ERR "File's private data is NULL.\n");
		return -EINVAL;
	}

	if (unlikely((size <= 0) || (size + slot_index) > MAX_GRANTS)) {
		printk(KERN_ERR "Invalid number of pages or offset"
		       "(num_pages = %d, first_slot = %ld).\n",
		       size, slot_index);
		return -ENXIO;
	}

	if ((vma->vm_flags & VM_WRITE) && !(vma->vm_flags & VM_SHARED)) {
		printk(KERN_ERR "Writable mappings must be shared.\n");
		return -EINVAL;
	}

	/* Slots must be in the NOT_YET_MAPPED state. */
	down_write(&private_data->grants_sem);
	for (i = 0; i < size; ++i) {
		if (private_data->grants[slot_index + i].state != 
		    GNTDEV_SLOT_NOT_YET_MAPPED) {
			printk(KERN_ERR "Slot (index = %ld) is in the wrong "
			       "state (%d).\n", slot_index + i, 
			       private_data->grants[slot_index + i].state);
			up_write(&private_data->grants_sem);
			return -EINVAL;
		}
	}

	/* Install the hook for unmapping. */
	vma->vm_ops = &gntdev_vmops;
    
	/* The VM area contains pages from another VM. */
	vma->vm_flags |= VM_FOREIGN;
	vma->vm_private_data = kzalloc(size * sizeof(struct page_struct *), 
				       GFP_KERNEL);
	if (vma->vm_private_data == NULL) {
		printk(KERN_ERR "Couldn't allocate mapping structure for VM "
		       "area.\n");
		return -ENOMEM;
	}

	/* This flag prevents Bad PTE errors when the memory is unmapped. */
	vma->vm_flags |= VM_RESERVED;

	/* This flag prevents this VM area being copied on a fork(). A better
	 * behaviour might be to explicitly carry out the appropriate mappings
	 * on fork(), but I don't know if there's a hook for this.
	 */
	vma->vm_flags |= VM_DONTCOPY;

	/* This flag ensures that the page tables are not unpinned before the
	 * VM area is unmapped. Therefore Xen still recognises the PTE as
	 * belonging to an L1 pagetable, and the grant unmap operation will
	 * succeed, even if the process does not exit cleanly.
	 */
	vma->vm_mm->context.has_foreign_mappings = 1;

	for (i = 0; i < size; ++i) {

		flags = GNTMAP_host_map;
		if (!(vma->vm_flags & VM_WRITE))
			flags |= GNTMAP_readonly;

		kernel_vaddr = get_kernel_vaddr(private_data, slot_index + i);
		user_vaddr = get_user_vaddr(vma, i);
		page = pfn_to_page(__pa(kernel_vaddr) >> PAGE_SHIFT);

		gnttab_set_map_op(&op, kernel_vaddr, flags,   
				  private_data->grants[slot_index+i]
				  .u.valid.ref, 
				  private_data->grants[slot_index+i]
				  .u.valid.domid);

		/* Carry out the mapping of the grant reference. */
		ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, 
						&op, 1);
		BUG_ON(ret);
		if (op.status) {
			printk(KERN_ERR "Error mapping the grant reference "
			       "into the kernel (%d). domid = %d; ref = %d\n",
			       op.status,
			       private_data->grants[slot_index+i]
			       .u.valid.domid,
			       private_data->grants[slot_index+i]
			       .u.valid.ref);
			goto undo_map_out;
		}

		/* Store a reference to the page that will be mapped into user
		 * space.
		 */
		((struct page **) vma->vm_private_data)[i] = page;

		/* Mark mapped page as reserved. */
		SetPageReserved(page);

		/* Record the grant handle, for use in the unmap operation. */
		private_data->grants[slot_index+i].u.valid.kernel_handle = 
			op.handle;
		private_data->grants[slot_index+i].u.valid.dev_bus_addr = 
			op.dev_bus_addr;
		
		private_data->grants[slot_index+i].state = GNTDEV_SLOT_MAPPED;
		private_data->grants[slot_index+i].u.valid.user_handle =
			GNTDEV_INVALID_HANDLE;

		/* Now perform the mapping to user space. */
		if (!xen_feature(XENFEAT_auto_translated_physmap)) {

			/* NOT USING SHADOW PAGE TABLES. */
			/* In this case, we map the grant(s) straight into user
			 * space.
			 */

			/* Get the machine address of the PTE for the user 
			 *  page.
			 */
			if ((ret = create_lookup_pte_addr(vma->vm_mm, 
							  vma->vm_start 
							  + (i << PAGE_SHIFT), 
							  &ptep)))
			{
				printk(KERN_ERR "Error obtaining PTE pointer "
				       "(%d).\n", ret);
				goto undo_map_out;
			}
			
			/* Configure the map operation. */
		
			/* The reference is to be used by host CPUs. */
			flags = GNTMAP_host_map;
			
			/* Specifies a user space mapping. */
			flags |= GNTMAP_application_map;
			
			/* The map request contains the machine address of the
			 * PTE to update.
			 */
			flags |= GNTMAP_contains_pte;
			
			if (!(vma->vm_flags & VM_WRITE))
				flags |= GNTMAP_readonly;

			gnttab_set_map_op(&op, ptep, flags, 
					  private_data->grants[slot_index+i]
					  .u.valid.ref, 
					  private_data->grants[slot_index+i]
					  .u.valid.domid);

			/* Carry out the mapping of the grant reference. */
			ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref,
							&op, 1);
			BUG_ON(ret);
			if (op.status) {
				printk(KERN_ERR "Error mapping the grant "
				       "reference into user space (%d). domid "
				       "= %d; ref = %d\n", op.status,
				       private_data->grants[slot_index+i].u
				       .valid.domid,
				       private_data->grants[slot_index+i].u
				       .valid.ref);
				goto undo_map_out;
			}
			
			/* Record the grant handle, for use in the unmap 
			 * operation. 
			 */
			private_data->grants[slot_index+i].u.
				valid.user_handle = op.handle;

			/* Update p2m structure with the new mapping. */
			set_phys_to_machine(__pa(kernel_vaddr) >> PAGE_SHIFT,
					    FOREIGN_FRAME(private_data->
							  grants[slot_index+i]
							  .u.valid.dev_bus_addr
							  >> PAGE_SHIFT));
		} else {
			/* USING SHADOW PAGE TABLES. */
			/* In this case, we simply insert the page into the VM
			 * area. */
			ret = vm_insert_page(vma, user_vaddr, page);
		}

	}

	up_write(&private_data->grants_sem);
	return 0;

undo_map_out:
	/* If we have a mapping failure, the unmapping will be taken care of
	 * by do_mmap_pgoff(), which will eventually call gntdev_clear_pte().
	 * All we need to do here is free the vma_private_data.
	 */
	kfree(vma->vm_private_data);

	/* THIS IS VERY UNPLEASANT: do_mmap_pgoff() will set the vma->vm_file
	 * to NULL on failure. However, we need this in gntdev_clear_pte() to
	 * unmap the grants. Therefore, we smuggle a reference to the file's
	 * private data in the VM area's private data pointer.
	 */
	vma->vm_private_data = private_data;
	
	up_write(&private_data->grants_sem);

	return -ENOMEM;
}

static pte_t gntdev_clear_pte(struct vm_area_struct *vma, unsigned long addr,
			      pte_t *ptep, int is_fullmm)
{
	int slot_index, ret;
	pte_t copy;
	struct gnttab_unmap_grant_ref op;
	gntdev_file_private_data_t *private_data;

	/* THIS IS VERY UNPLEASANT: do_mmap_pgoff() will set the vma->vm_file
	 * to NULL on failure. However, we need this in gntdev_clear_pte() to
	 * unmap the grants. Therefore, we smuggle a reference to the file's
	 * private data in the VM area's private data pointer.
	 */
	if (vma->vm_file) {
		private_data = (gntdev_file_private_data_t *)
			vma->vm_file->private_data;
	} else if (vma->vm_private_data) {
		private_data = (gntdev_file_private_data_t *)
			vma->vm_private_data;
	} else {
		private_data = NULL; /* gcc warning */
		BUG();
	}

	/* Copy the existing value of the PTE for returning. */
	copy = *ptep;

	/* Calculate the grant relating to this PTE. */
	slot_index = vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT);

	/* Only unmap grants if the slot has been mapped. This could be being
	 * called from a failing mmap().
	 */
	if (private_data->grants[slot_index].state == GNTDEV_SLOT_MAPPED) {

		/* First, we clear the user space mapping, if it has been made.
		 */
		if (private_data->grants[slot_index].u.valid.user_handle !=
		    GNTDEV_INVALID_HANDLE && 
		    !xen_feature(XENFEAT_auto_translated_physmap)) {
			/* NOT USING SHADOW PAGE TABLES. */
			gnttab_set_unmap_op(&op, virt_to_machine(ptep), 
					    GNTMAP_contains_pte,
					    private_data->grants[slot_index]
					    .u.valid.user_handle);
			ret = HYPERVISOR_grant_table_op(
				GNTTABOP_unmap_grant_ref, &op, 1);
			BUG_ON(ret);
			if (op.status)
				printk("User unmap grant status = %d\n", 
				       op.status);
		} else {
			/* USING SHADOW PAGE TABLES. */
			pte_clear_full(vma->vm_mm, addr, ptep, is_fullmm);
		}

		/* Finally, we unmap the grant from kernel space. */
		gnttab_set_unmap_op(&op, 
				    get_kernel_vaddr(private_data, slot_index),
				    GNTMAP_host_map, 
				    private_data->grants[slot_index].u.valid
				    .kernel_handle);
		ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, 
						&op, 1);
		BUG_ON(ret);
		if (op.status)
			printk("Kernel unmap grant status = %d\n", op.status);


		/* Return slot to the not-yet-mapped state, so that it may be
		 * mapped again, or removed by a subsequent ioctl.
		 */
		private_data->grants[slot_index].state = 
			GNTDEV_SLOT_NOT_YET_MAPPED;

		/* Invalidate the physical to machine mapping for this page. */
		set_phys_to_machine(__pa(get_kernel_vaddr(private_data, 
							  slot_index)) 
				    >> PAGE_SHIFT, INVALID_P2M_ENTRY);

	} else {
		pte_clear_full(vma->vm_mm, addr, ptep, is_fullmm);
	}

	return copy;
}

/* "Destructor" for a VM area.
 */
static void gntdev_vma_close(struct vm_area_struct *vma) {
	if (vma->vm_private_data) {
		kfree(vma->vm_private_data);
	}
}

/* Called when an ioctl is made on the device.
 */
static int gntdev_ioctl(struct inode *inode, struct file *flip,
			unsigned int cmd, unsigned long arg)
{
	int rc = 0;
	gntdev_file_private_data_t *private_data = 
		(gntdev_file_private_data_t *) flip->private_data;

	switch (cmd) {
	case IOCTL_GNTDEV_MAP_GRANT_REF:
	{
		struct ioctl_gntdev_map_grant_ref op;
		down_write(&private_data->grants_sem);
		down_write(&private_data->free_list_sem);

		if ((rc = copy_from_user(&op, (void __user *) arg, 
					 sizeof(op)))) {
			rc = -EFAULT;
			goto map_out;
		}
		if (unlikely(op.count <= 0)) {
			rc = -EINVAL;
			goto map_out;
		}

		if (op.count == 1) {
			if ((rc = add_grant_reference(flip, &op.refs[0],
						      &op.index)) < 0) {
				printk(KERN_ERR "Adding grant reference "
				       "failed (%d).\n", rc);
				goto map_out;
			}
		} else {
			struct ioctl_gntdev_grant_ref *refs, *u;
			refs = kmalloc(op.count * sizeof(*refs), GFP_KERNEL);
			if (!refs) {
				rc = -ENOMEM;
				goto map_out;
			}
			u = ((struct ioctl_gntdev_map_grant_ref *)arg)->refs;
			if ((rc = copy_from_user(refs,
						 (void __user *)u,
						 sizeof(*refs) * op.count))) {
				printk(KERN_ERR "Copying refs from user failed"
				       " (%d).\n", rc);
				rc = -EINVAL;
				goto map_out;
			}
			if ((rc = find_contiguous_free_range(flip, op.count))
			    < 0) {
				printk(KERN_ERR "Finding contiguous range "
				       "failed (%d).\n", rc);
				kfree(refs);
				goto map_out;
			}
			op.index = rc << PAGE_SHIFT;
			if ((rc = add_grant_references(flip, op.count,
						       refs, rc))) {
				printk(KERN_ERR "Adding grant references "
				       "failed (%d).\n", rc);
				kfree(refs);
				goto map_out;
			}
			compress_free_list(flip);
			kfree(refs);
		}
		if ((rc = copy_to_user((void __user *) arg, 
				       &op, 
				       sizeof(op)))) {
			printk(KERN_ERR "Copying result back to user failed "
			       "(%d)\n", rc);
			rc = -EFAULT;
			goto map_out;
		}
	map_out:
		up_write(&private_data->grants_sem);
		up_write(&private_data->free_list_sem);
		return rc;
	}
	case IOCTL_GNTDEV_UNMAP_GRANT_REF:
	{
		struct ioctl_gntdev_unmap_grant_ref op;
		int i, start_index;

		down_write(&private_data->grants_sem);
		down_write(&private_data->free_list_sem);

		if ((rc = copy_from_user(&op, 
					 (void __user *) arg, 
					 sizeof(op)))) {
			rc = -EFAULT;
			goto unmap_out;
		}

		start_index = op.index >> PAGE_SHIFT;

		/* First, check that all pages are in the NOT_YET_MAPPED
		 * state.
		 */
		for (i = 0; i < op.count; ++i) {
			if (unlikely
			    (private_data->grants[start_index + i].state
			     != GNTDEV_SLOT_NOT_YET_MAPPED)) {
				if (private_data->grants[start_index + i].state
				    == GNTDEV_SLOT_INVALID) {
					printk(KERN_ERR
					       "Tried to remove an invalid "
					       "grant at offset 0x%x.",
					       (start_index + i) 
					       << PAGE_SHIFT);
					rc = -EINVAL;
				} else {
					printk(KERN_ERR
					       "Tried to remove a grant which "
					       "is currently mmap()-ed at "
					       "offset 0x%x.",
					       (start_index + i) 
					       << PAGE_SHIFT);
					rc = -EBUSY;
				}
				goto unmap_out;
			}
		}

		/* Unmap pages and add them to the free list.
		 */
		for (i = 0; i < op.count; ++i) {
			private_data->grants[start_index+i].state = 
				GNTDEV_SLOT_INVALID;
			private_data->grants[start_index+i].u.free_list_index =
				private_data->free_list_size;
			private_data->free_list[private_data->free_list_size] =
				start_index + i;
			++private_data->free_list_size;
		}
		compress_free_list(flip);

	unmap_out:
		up_write(&private_data->grants_sem);
		up_write(&private_data->free_list_sem);
		return rc;
	}
	case IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR:
	{
		struct ioctl_gntdev_get_offset_for_vaddr op;
		struct vm_area_struct *vma;
		unsigned long vaddr;

		if ((rc = copy_from_user(&op, 
					 (void __user *) arg, 
					 sizeof(op)))) {
			rc = -EFAULT;
			goto get_offset_out;
		}
		vaddr = (unsigned long)op.vaddr;

		down_read(&current->mm->mmap_sem);		
		vma = find_vma(current->mm, vaddr);
		if (vma == NULL) {
			rc = -EFAULT;
			goto get_offset_unlock_out;
		}
		if ((!vma->vm_ops) || (vma->vm_ops != &gntdev_vmops)) {
			printk(KERN_ERR "The vaddr specified does not belong "
			       "to a gntdev instance: %#lx\n", vaddr);
			rc = -EFAULT;
			goto get_offset_unlock_out;
		}
		if (vma->vm_start != vaddr) {
			printk(KERN_ERR "The vaddr specified in an "
			       "IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR must be at "
			       "the start of the VM area. vma->vm_start = "
			       "%#lx; vaddr = %#lx\n",
			       vma->vm_start, vaddr);
			rc = -EFAULT;
			goto get_offset_unlock_out;
		}
		op.offset = vma->vm_pgoff << PAGE_SHIFT;
		op.count = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
		up_read(&current->mm->mmap_sem);
		if ((rc = copy_to_user((void __user *) arg, 
				       &op, 
				       sizeof(op)))) {
			rc = -EFAULT;
			goto get_offset_out;
		}
		goto get_offset_out;
	get_offset_unlock_out:
		up_read(&current->mm->mmap_sem);
	get_offset_out:
		return rc;
	}
	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

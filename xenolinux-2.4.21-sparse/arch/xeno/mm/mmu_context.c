
#include <linux/slab.h>
#include <linux/list.h>

int init_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
    INIT_LIST_HEAD(&mm->context.direct_list);
    return 0;
}

/* just free all elements of list identifying directly mapped areas */
void destroy_context(struct mm_struct *mm)
{
    direct_mmap_node_t * node;
    struct list_head * curr;
    struct list_head * direct_list = &mm->context.direct_list;

    curr = direct_list->next;
    while(curr != direct_list){
        node = list_entry(curr, direct_mmap_node_t, list);
        curr = curr->next;
        list_del(&node->list);
        kfree(node);
   }

}

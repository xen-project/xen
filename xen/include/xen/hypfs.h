#ifndef __XEN_HYPFS_H__
#define __XEN_HYPFS_H__

#ifdef CONFIG_HYPFS
#include <xen/list.h>
#include <xen/string.h>
#include <public/hypfs.h>

struct hypfs_entry_leaf;

struct hypfs_entry {
    unsigned short type;
    unsigned short encoding;
    unsigned int size;
    unsigned int max_size;
    const char *name;
    struct list_head list;
    int (*read)(const struct hypfs_entry *entry,
                XEN_GUEST_HANDLE_PARAM(void) uaddr);
    int (*write)(struct hypfs_entry_leaf *leaf,
                 XEN_GUEST_HANDLE_PARAM(void) uaddr, unsigned int ulen);
};

struct hypfs_entry_leaf {
    struct hypfs_entry e;
    union {
        const void *content;
        void *write_ptr;
    };
};

struct hypfs_entry_dir {
    struct hypfs_entry e;
    struct list_head dirlist;
};

#define HYPFS_DIR_INIT(var, nam)                  \
    struct hypfs_entry_dir __read_mostly var = {  \
        .e.type = XEN_HYPFS_TYPE_DIR,             \
        .e.encoding = XEN_HYPFS_ENC_PLAIN,        \
        .e.name = (nam),                          \
        .e.size = 0,                              \
        .e.max_size = 0,                          \
        .e.list = LIST_HEAD_INIT(var.e.list),     \
        .e.read = hypfs_read_dir,                 \
        .dirlist = LIST_HEAD_INIT(var.dirlist),   \
    }

#define HYPFS_VARSIZE_INIT(var, typ, nam, msz)    \
    struct hypfs_entry_leaf __read_mostly var = { \
        .e.type = (typ),                          \
        .e.encoding = XEN_HYPFS_ENC_PLAIN,        \
        .e.name = (nam),                          \
        .e.max_size = (msz),                      \
        .e.read = hypfs_read_leaf,                \
    }

/* Content and size need to be set via hypfs_string_set_reference(). */
#define HYPFS_STRING_INIT(var, nam)               \
    HYPFS_VARSIZE_INIT(var, XEN_HYPFS_TYPE_STRING, nam, 0)

/*
 * Set content and size of a XEN_HYPFS_TYPE_STRING node. The node will point
 * to str, so any later modification of *str should be followed by a call
 * to hypfs_string_set_reference() in order to update the size of the node
 * data.
 */
static inline void hypfs_string_set_reference(struct hypfs_entry_leaf *leaf,
                                              const char *str)
{
    leaf->content = str;
    leaf->e.size = strlen(str) + 1;
}

#define HYPFS_FIXEDSIZE_INIT(var, typ, nam, contvar, wr) \
    struct hypfs_entry_leaf __read_mostly var = {        \
        .e.type = (typ),                                 \
        .e.encoding = XEN_HYPFS_ENC_PLAIN,               \
        .e.name = (nam),                                 \
        .e.size = sizeof(contvar),                       \
        .e.max_size = (wr) ? sizeof(contvar) : 0,        \
        .e.read = hypfs_read_leaf,                       \
        .e.write = (wr),                                 \
        .content = &(contvar),                           \
    }

#define HYPFS_UINT_INIT(var, nam, contvar)                       \
    HYPFS_FIXEDSIZE_INIT(var, XEN_HYPFS_TYPE_UINT, nam, contvar, NULL)
#define HYPFS_UINT_INIT_WRITABLE(var, nam, contvar)              \
    HYPFS_FIXEDSIZE_INIT(var, XEN_HYPFS_TYPE_UINT, nam, contvar, \
                         hypfs_write_leaf)

#define HYPFS_INT_INIT(var, nam, contvar)                        \
    HYPFS_FIXEDSIZE_INIT(var, XEN_HYPFS_TYPE_INT, nam, contvar, NULL)
#define HYPFS_INT_INIT_WRITABLE(var, nam, contvar)               \
    HYPFS_FIXEDSIZE_INIT(var, XEN_HYPFS_TYPE_INT, nam, contvar, \
                         hypfs_write_leaf)

#define HYPFS_BOOL_INIT(var, nam, contvar)                       \
    HYPFS_FIXEDSIZE_INIT(var, XEN_HYPFS_TYPE_BOOL, nam, contvar, NULL)
#define HYPFS_BOOL_INIT_WRITABLE(var, nam, contvar)              \
    HYPFS_FIXEDSIZE_INIT(var, XEN_HYPFS_TYPE_BOOL, nam, contvar, \
                         hypfs_write_bool)

extern struct hypfs_entry_dir hypfs_root;

int hypfs_add_dir(struct hypfs_entry_dir *parent,
                  struct hypfs_entry_dir *dir, bool nofault);
int hypfs_add_leaf(struct hypfs_entry_dir *parent,
                   struct hypfs_entry_leaf *leaf, bool nofault);
int hypfs_read_dir(const struct hypfs_entry *entry,
                   XEN_GUEST_HANDLE_PARAM(void) uaddr);
int hypfs_read_leaf(const struct hypfs_entry *entry,
                    XEN_GUEST_HANDLE_PARAM(void) uaddr);
int hypfs_write_leaf(struct hypfs_entry_leaf *leaf,
                     XEN_GUEST_HANDLE_PARAM(void) uaddr, unsigned int ulen);
int hypfs_write_bool(struct hypfs_entry_leaf *leaf,
                     XEN_GUEST_HANDLE_PARAM(void) uaddr, unsigned int ulen);
#endif

#endif /* __XEN_HYPFS_H__ */

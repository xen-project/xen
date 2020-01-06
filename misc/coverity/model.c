/* Coverity Scan model
 *
 * This is a modelling file for Coverity Scan. Modelling helps to avoid false
 * positives.
 *
 * - A model file can't import any header files.
 * - Therefore only some built-in primitives like int, char and void are
 *   available but not NULL etc.
 * - Modelling doesn't need full structs and typedefs. Rudimentary structs
 *   and similar types are sufficient.
 * - An uninitialised local pointer is not an error. It signifies that the
 *   variable could be either NULL or have some data.
 *
 * Coverity Scan doesn't pick up modifications automatically. The model file
 * must be uploaded by an admin in the analysis.
 *
 * The Xen Coverity Scan modelling file used the cpython modelling file as a
 * reference to get started (suggested by Coverty Scan themselves as a good
 * example), but all content is Xen specific.
 *
 * Copyright (c) 2013-2014 Citrix Systems Ltd; All Right Reserved
 *
 * Based on:
 *     http://hg.python.org/cpython/file/tip/Misc/coverity_model.c
 * Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
 * 2011, 2012, 2013 Python Software Foundation; All Rights Reserved
 *
 */

/*
 * Useful references:
 *   https://scan.coverity.com/models
 */

/* Definitions */
#define NULL (void *)0
#define PAGE_SIZE 4096UL
#define PAGE_MASK (~(PAGE_SIZE-1))

#define assert(cond) /* empty */

struct page_info {};
struct pthread_mutex_t {};

struct libxl__ctx
{
    struct pthread_mutex_t lock;
};
typedef struct libxl__ctx libxl_ctx;

/*
 * Xen malloc.  Behaves exactly like regular malloc(), except it also contains
 * an alignment parameter.
 *
 * TODO: work out how to correctly model bad alignments as errors.
 */
void *_xmalloc(unsigned long size, unsigned long align)
{
    int has_memory;

    __coverity_negative_sink__(size);
    __coverity_negative_sink__(align);

    if ( has_memory )
        return __coverity_alloc__(size);
    else
        return NULL;
}

/*
 * Xen free.  Frees a pointer allocated by _xmalloc().
 */
void xfree(void *va)
{
    __coverity_free__(va);
}


/*
 * map_domain_page() takes an existing domain page and possibly maps it into
 * the Xen pagetables, to allow for direct access.  Model this as a memory
 * allocation of exactly 1 page.
 *
 * map_domain_page() never fails. (It will BUG() before returning NULL)
 */
void *map_domain_page(unsigned long mfn)
{
    unsigned long ptr = (unsigned long)__coverity_alloc__(PAGE_SIZE);

    /*
     * Expressing the alignment of the memory allocation isn't possible.  As a
     * substitute, tell Coverity to ignore any path where ptr isn't page
     * aligned.
     */
    if ( ptr & ~PAGE_MASK )
        __coverity_panic__();

    return (void *)ptr;
}

/*
 * unmap_domain_page() will unmap a page.  Model it as a free().  Any *va
 * within the page is valid to pass.
 */
void unmap_domain_page(const void *va)
{
    unsigned long ptr = (unsigned long)va & PAGE_MASK;

    __coverity_free__((void *)ptr);
}

/*
 * Coverity appears not to understand that errx() unconditionally exits.
 */
void errx(int, const char*, ...)
{
    __coverity_panic__();
}

/*
 * Coverity doesn't appear to be certain that the libxl ctx->lock is recursive.
 */
void libxl__ctx_lock(libxl_ctx *ctx)
{
    __coverity_recursive_lock_acquire__(&ctx->lock);
}

void libxl__ctx_unlock(libxl_ctx *ctx)
{
    __coverity_recursive_lock_release__(&ctx->lock);
}

/*
 * Coverity doesn't understand __builtin_unreachable(), which causes it to
 * incorrectly find issues based on continuing execution along the false
 * branch of an ASSERT().
 */
void __builtin_unreachable(void)
{
    __coverity_panic__();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

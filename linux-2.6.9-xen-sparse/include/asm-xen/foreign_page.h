/******************************************************************************
 * foreign_page.h
 * 
 * Provide a "foreign" page type, that is owned by a foreign allocator and 
 * not the normal buddy allocator in page_alloc.c
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __ASM_XEN_FOREIGN_PAGE_H__
#define __ASM_XEN_FOREIGN_PAGE_H__

#define PG_foreign		PG_arch_1

#define PageForeign(page)	test_bit(PG_foreign, &(page)->flags)

#define SetPageForeign(page, dtor) do {		\
	set_bit(PG_foreign, &(page)->flags);	\
	(page)->mapping = (void *)dtor;		\
} while (0)

#define ClearPageForeign(page) do {		\
	clear_bit(PG_foreign, &(page)->flags);	\
	(page)->mapping = NULL;			\
} while (0)

#define PageForeignDestructor(page)	\
	( (void (*) (struct page *)) (page)->mapping )

#endif /* __ASM_XEN_FOREIGN_PAGE_H__ */

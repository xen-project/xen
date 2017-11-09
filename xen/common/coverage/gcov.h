#ifndef _GCOV_H_
#define _GCOV_H_

#include <xen/guest_access.h>
#include <xen/types.h>

/*
 * Profiling data types used for gcc 3.4 and above - these are defined by
 * gcc and need to be kept as close to the original definition as possible to
 * remain compatible.
 */
#define GCOV_DATA_MAGIC         ((unsigned int)0x67636461)
#define GCOV_TAG_FUNCTION       ((unsigned int)0x01000000)
#define GCOV_TAG_COUNTER_BASE   ((unsigned int)0x01a10000)
#define GCOV_TAG_FOR_COUNTER(count)				\
	GCOV_TAG_COUNTER_BASE + ((unsigned int)(count) << 17)

#define GCC_VERSION (__GNUC__ * 10000           \
                     + __GNUC_MINOR__ * 100     \
                     + __GNUC_PATCHLEVEL__)

#if BITS_PER_LONG >= 64
typedef long gcov_type;
#else
typedef long long gcov_type;
#endif

/* Opaque gcov_info -- tied to specific gcc gcov formats */
struct gcov_info;

void gcov_info_link(struct gcov_info *info);
struct gcov_info *gcov_info_next(const struct gcov_info *info);
void gcov_info_reset(struct gcov_info *info);
const char *gcov_info_filename(const struct gcov_info *info);
size_t gcov_info_to_gcda(char *buffer, const struct gcov_info *info);

size_t gcov_store_uint32(void *buffer, size_t off, uint32_t v);
size_t gcov_store_uint64(void *buffer, size_t off, uint64_t v);

#endif	/* _GCOV_H_ */

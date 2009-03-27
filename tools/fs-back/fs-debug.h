#ifndef __FS_DEBUG__
#define __FS_DEBUG__

// #define DEBUG 1

#ifdef DEBUG
#define FS_DEBUG(fmt, ...) do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define FS_DEBUG(fmt, ...) do { } while (0)
#endif

#endif /*__FS_DEBUG__*/

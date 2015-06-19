#define MREAD_MAPS 8
#define MREAD_BUF_SHIFT 9
#define PAGE_SHIFT 12
#define MREAD_BUF_SIZE (1ULL<<(PAGE_SHIFT+MREAD_BUF_SHIFT))
#define MREAD_BUF_MASK (~(MREAD_BUF_SIZE-1))
typedef struct mread_ctrl {
    int fd;
    off_t file_size;
    struct mread_buffer {
        char * buffer;
        off_t start_offset;
        int accessed;
    } map[MREAD_MAPS];
    int clock, last;
} *mread_handle_t;

mread_handle_t mread_init(int fd);
ssize_t mread64(mread_handle_t h, void *dst, ssize_t len, off_t offset);

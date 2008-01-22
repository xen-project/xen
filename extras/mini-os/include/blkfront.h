#include <wait.h>
#include <xen/io/blkif.h>
#include <types.h>
struct blkfront_dev;
struct blkfront_aiocb
{
    struct blkfront_dev *aio_dev;
    uint8_t *aio_buf;
    size_t aio_nbytes;
    uint64_t aio_offset;
    void *data;

    grant_ref_t gref[BLKIF_MAX_SEGMENTS_PER_REQUEST];

    void (*aio_cb)(struct blkfront_aiocb *aiocb, int ret);
};
struct blkfront_dev *init_blkfront(char *nodename, uint64_t *sectors, unsigned *sector_size, int *mode);
#ifdef HAVE_LIBC
int blkfront_open(struct blkfront_dev *dev);
#endif
void blkfront_aio(struct blkfront_aiocb *aiocbp, int write);
void blkfront_aio_read(struct blkfront_aiocb *aiocbp);
void blkfront_aio_write(struct blkfront_aiocb *aiocbp);
int blkfront_aio_poll(struct blkfront_dev *dev);
void blkfront_sync(struct blkfront_dev *dev);
void shutdown_blkfront(struct blkfront_dev *dev);

extern struct wait_queue_head blkfront_queue;

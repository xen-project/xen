
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/poll.h>

#include "libgnbd.h"

#define PRINTF(x) printf x
#if 0
#define DFPRINTF(x...) fprintf(stderr, ##x)
#define DPRINTF(x) DFPRINTF x
#else
#define DPRINTF(x)
#endif

static unsigned char buf1[8 << 9];
static unsigned char buf2[8 << 9];
static unsigned char buf3[8 << 9];

int
main(int argc, char **argv)
{
	struct gnbd_handle *gh;
	struct pollfd pfd[1];
	int err, tout;

	gh = gnbd_setup("panik", 0x38e7, "cl349-nahant-beta2-root1",
	    "arcadians.cl.cam.ac.uk");
	if (gh == NULL)
		errx(1, "gnbd_setup");

	memset(pfd, 0, sizeof(pfd));
	pfd[0].fd = gnbd_fd(gh);
	pfd[0].events = POLLIN;

	while ((tout = poll(pfd, 1, 0)) >= 0) {
		if (tout == 0)
			continue;
		DPRINTF(("event\n"));
		if (pfd[0].revents) {
			err = gnbd_reply(gh);
			pfd[0].events = POLLIN;
			switch (err) {
			case GNBD_LOGIN_DONE:
				DPRINTF(("sectors: %08llu\n",
					    gnbd_sectors(gh)));
				err = gnbd_read(gh, 8, 8, buf2, 1);
				if (err)
					warnx("gnbd_read");
				err = gnbd_read(gh, 0, 8, buf1, 0);
				if (err)
					warnx("gnbd_read");
				err = gnbd_read(gh, 16, 8, buf3, 2);
				if (err)
					warnx("gnbd_read");
				break;
			case GNBD_REQUEST_DONE:
				DPRINTF(("request done %ld\n",
					    gnbd_finished_request(gh)));
				if (0 && gnbd_finished_request(gh) == 0) {
					write(1, buf1, 8 << 9);
					err = gnbd_write(gh, 0, 8, buf1, 10);
					if (err)
						warnx("gnbd_write");
				}
				break;
			case GNBD_CONTINUE:
				DPRINTF(("continue\n"));
				break;
			case 0:
				break;
			case GNBD_CONTINUE_WRITE:
				DPRINTF(("continue write\n"));
				pfd[0].events |= POLLOUT;
				break;
			default:
				warnx("gnbd_reply error");
				break;
			}
			DPRINTF(("got gnbd reply\n"));
		}
	}

	return 0;
}

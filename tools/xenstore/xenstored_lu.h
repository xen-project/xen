/* SPDX-License-Identifier: MIT */

/*
 * Live Update interfaces for Xen Store Daemon.
 * Copyright (C) 2022 Juergen Gross, SUSE LLC
 */

#ifndef NO_LIVE_UPDATE
struct live_update {
	/* For verification the correct connection is acting. */
	struct connection *conn;

	/* Pointer to the command used to request LU */
	struct buffered_data *in;

#ifdef __MINIOS__
	void *kernel;
	unsigned int kernel_size;
	unsigned int kernel_off;

	void *dump_state;
	unsigned long dump_size;
#else
	char *filename;
#endif

	char *cmdline;

	/* Start parameters. */
	bool force;
	unsigned int timeout;
	time_t started_at;
};

struct lu_dump_state {
	void *buf;
	unsigned int size;
#ifndef __MINIOS__
	int fd;
	char *filename;
#endif
};

extern struct live_update *lu_status;

struct connection *lu_get_connection(void);
bool lu_is_pending(void);
void lu_read_state(void);

/* Write the "OK" response for the live-update command */
unsigned int lu_write_response(FILE *fp);

int do_control_lu(const void *ctx, struct connection *conn, char **vec,
		  int num);

/* Live update private interfaces. */
void lu_get_dump_state(struct lu_dump_state *state);
void lu_close_dump_state(struct lu_dump_state *state);
FILE *lu_dump_open(const void *ctx);
void lu_dump_close(FILE *fp);
char *lu_exec(const void *ctx, int argc, char **argv);
const char *lu_arch(const void *ctx, struct connection *conn, char **vec,
		    int num);
const char *lu_begin(struct connection *conn);
void lu_destroy_arch(void *data);
#else
static inline struct connection *lu_get_connection(void)
{
	return NULL;
}

static inline unsigned int lu_write_response(FILE *fp)
{
	return 0;
}

static inline bool lu_is_pending(void)
{
	return false;
}
#endif

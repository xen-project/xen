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

#endif

	char *filename;
	char *cmdline;

	/* Start parameters. */
	bool force;
	unsigned int timeout;
	time_t started_at;
};

extern struct live_update *lu_status;

struct connection *lu_get_connection(void);
bool lu_is_pending(void);
void lu_read_state(void);

/* Write the "OK" response for the live-update command */
unsigned int lu_write_response(FILE *fp);

int do_control_lu(const void *ctx, struct connection *conn, const char **vec,
		  int num);

/* Live update private interfaces. */
char *lu_exec(const void *ctx, int argc, char **argv);
const char *lu_arch(const void *ctx, struct connection *conn, const char **vec,
		    int num);
const char *lu_begin(struct connection *conn);
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

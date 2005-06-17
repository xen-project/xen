/* Stress test for Xen Store: multiple people hammering transactions */
#include "xs.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define NUM_HANDLES 2
#define DIR_FANOUT 3
#define DIR_DEPTH 3

/* How often to print progress */
static int print;

/* Layout looks like /<num>/<num>/count. */
static void work(unsigned int cycles, unsigned int childnum)
{
	unsigned int i;
	struct xs_handle *handles[NUM_HANDLES];
	char id;

	if (childnum < 10)
		id = '0' + childnum;
	else
		id = 'A' + childnum - 10;

	for (i = 0; i < NUM_HANDLES; i++) {
		handles[i] = xs_daemon_open();
		if (!handles[i])
			barf_perror("Opening handle %i", i);
	}

	srandom(childnum);
	for (i = 0; i < cycles; i++) {
		unsigned int lockdepth, j, len;
		char file[100] = "", lockdir[100];
		char *contents, tmp[100];
		struct xs_handle *h = handles[random() % NUM_HANDLES];

		lockdepth = random() % DIR_DEPTH;
		for (j = 0; j < DIR_DEPTH; j++) {
			if (j == lockdepth)
				strcpy(lockdir, file);
			sprintf(file + strlen(file), "/%li",
				random()%DIR_FANOUT);
		}
		if (streq(lockdir, ""))
			strcpy(lockdir, "/");

		if (!xs_transaction_start(h, lockdir))
			barf_perror("%i: starting transaction %i on %s",
				    childnum, i, lockdir);

		sprintf(file + strlen(file), "/count");
		contents = xs_read(h, file, &len);
		if (!contents)
			barf_perror("%i: can't read %s iter %i",
				    childnum, file, i);
		sprintf(tmp, "%i", atoi(contents) + 1);
		if (!xs_write(h, file, tmp, strlen(tmp)+1, 0))
			barf_perror("%i: can't write %s iter %i",
				    childnum, file, i);

		/* Abandon 1 in 10 */
		if (random() % 10 == 0) {
			if (!xs_transaction_end(h, true))
				barf_perror("%i: can't abort transact %s",
					    childnum, lockdir);
			i--;
		} else {
			if (!xs_transaction_end(h, false))
				barf_perror("%i: can't commit transact %s",
					    childnum, lockdir);

			/* Offset when we print . so kids don't all
			 * print at once. */
			if ((i + print/(childnum+1)) % print == 0)
				write(STDOUT_FILENO, &id, 1);
		}
	}
}

static void create_dirs(struct xs_handle *h, const char *base, int togo)
{
	unsigned int i;
	char filename[100];

	if (togo == 0) {
		sprintf(filename, "%s/count", base);
		if (!xs_write(h, filename, "0", 2, O_EXCL|O_CREAT))
			barf_perror("Writing to %s", filename);
		return;
	}

	for (i = 0; i < DIR_FANOUT; i++) {
		sprintf(filename, "%s/%i", base, i);
		if (!xs_mkdir(h, filename))
			barf_perror("xs_mkdir %s", filename);
		create_dirs(h, filename, togo-1);
	}
}

static unsigned int add_count(struct xs_handle *h, const char *base, int togo)
{
	unsigned int i, count;
	char filename[100];

	if (togo == 0) {
		char *answer;
		unsigned int len;

		sprintf(filename, "%s/count", base);
		answer = xs_read(h, filename, &len);
		if (!answer)
			barf_perror("Reading %s", filename);
		count = atoi(answer);
		free(answer);
		return count;
	}

	count = 0;
	for (i = 0; i < DIR_FANOUT; i++) {
		sprintf(filename, "%s/%i", base, i);
		count += add_count(h, filename, togo-1);
	}
	return count;
}

static void setup(void)
{
	struct xs_handle *h;

	/* Do setup. */
	h = xs_daemon_open();
	if (!h)
		barf_perror("Contacting daemon");
	create_dirs(h, "", DIR_DEPTH);
	xs_daemon_close(h);
}

static unsigned int tally_counts(void)
{
	struct xs_handle *h;
	unsigned int ret;
	
	h = xs_daemon_open();
	if (!h)
		barf_perror("Contacting daemon");

	ret = add_count(h, "", DIR_DEPTH);
	xs_daemon_close(h);
	return ret;
}	

int main(int argc, char *argv[])
{
	unsigned int i;
	bool failed = false;
	int kids[10];

	if (argc != 2)
		barf("Usage: xs_stress <iterations>");

	printf("Setting up directories...\n");
	setup();

	print = atoi(argv[1]) / 76;
	if (!print)
		print = 1;

	printf("Running %i children...\n", ARRAY_SIZE(kids));
	for (i = 0; i < ARRAY_SIZE(kids); i++) {
		kids[i] = fork();
		if (kids[i] == -1)
			barf_perror("fork");
		if (kids[i] == 0) {
			work(atoi(argv[1]) / ARRAY_SIZE(kids), i);
			exit(0);
		}
	}

	for (i = 0; i < ARRAY_SIZE(kids); i++) {
		int status;
		if (waitpid(kids[i], &status, 0) == -1)
			barf_perror("waitpid");
		if (!WIFEXITED(status))
			barf("Kid %i died via signal %i\n",
			     i, WTERMSIG(status));
		if (WEXITSTATUS(status) != 0) {
			printf("Child %i exited %i\n", i, WEXITSTATUS(status));
			failed = true;
		}
	}
	if (failed)
		exit(1);

	printf("\nCounting results...\n");
	i = tally_counts();
	if (i != (unsigned)atoi(argv[1]))
		barf("Total counts %i not %s", i, atoi(argv[1]));
	printf("Success!\n");
	exit(0);
}

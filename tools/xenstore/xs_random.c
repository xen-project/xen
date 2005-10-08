/* Random tests.

   We check that the results from a real filesystem are the same.
*/
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include "xs.h"
#include "talloc.h"
#include "utils.h"

struct ops
{
	char *name;

	char **(*dir)(void *h, const char *path, unsigned int *num);

	void *(*read)(void *h, const char *path, unsigned int *len);

	bool (*write)(void *h, const char *path, const void *data,
		      unsigned int len);

	bool (*mkdir)(void *h, const char *path);

	bool (*rm)(void *h, const char *path);

	struct xs_permissions *(*get_perms)(void *h,
					    const char *path,
					    unsigned int *num);

	bool (*set_perms)(void *h,
			  const char *path,
			  struct xs_permissions *perms,
			  unsigned int num);

	bool (*transaction_start)(void *h);
	bool (*transaction_end)(void *h, bool abort);

	/* Create and destroy a new handle. */
	void *(*handle)(const char *path);
	void (*close)(void *);
};

struct file_ops_info
{
	const char *base;
	char *transact_base;
};

static void convert_to_dir(const char *dirname)
{
	char *tmpname = talloc_asprintf(dirname, "%s.tmp", dirname);
	if (rename(dirname, tmpname) != 0)
		barf_perror("Failed to rename %s to %s", dirname, tmpname);
	if (mkdir(dirname, 0700) != 0) 
		barf_perror("Failed to mkdir %s", dirname);
	if (rename(tmpname,talloc_asprintf(dirname, "%s/.DATA", dirname)) != 0)
		barf_perror("Failed to rename into %s", dirname);
	/* If perms exists, move it in. */
	rename(talloc_asprintf(dirname, "%s.perms", dirname),
	       talloc_asprintf(dirname, "%s/.perms", dirname));
}

/* Files can be used as dirs, too.  Convert them when they are. */
static void maybe_convert_to_directory(const char *filename)
{
	struct stat st;
	char *dirname = talloc_asprintf(
		filename, "%.*s",
		(int)(strrchr(filename, '/') - filename), filename);
	if (lstat(dirname, &st) == 0 && S_ISREG(st.st_mode))
		convert_to_dir(dirname);
}

static char *get_name(struct file_ops_info *info, const char *path)
{
	if (info->transact_base)
		return talloc_asprintf(path, "%s%s", info->transact_base,
				       path);
	return talloc_asprintf(path, "%s%s", info->base, path);
}

static char *path_to_name(struct file_ops_info *info, const char *path)
{
	char *filename = get_name(info, path);
	maybe_convert_to_directory(filename);
	return filename;
}

static char **file_directory(struct file_ops_info *info,
			     const char *path, unsigned int *num)
{
	char **ret;
	DIR *dir;
	struct dirent *dirent;
	char *p, *dirname = path_to_name(info, path);
	unsigned int i, len = 0;
	struct stat st;

	/* If it exists, but isn't a directory, we convert it. */
	if (lstat(dirname, &st) == 0 && !S_ISDIR(st.st_mode))
		convert_to_dir(dirname);

	*num = 0;
	dir = opendir(dirname);
	if (!dir)
		return NULL;;

	/* Once to count them. */
	while ((dirent = readdir(dir)) != NULL) {
		if (strchr(dirent->d_name, '.'))
			continue;
		len += strlen(dirent->d_name) + 1;
		(*num)++;
	}
	rewinddir(dir);

	/* Now allocate and fill in. */
	ret = malloc(sizeof(char *) * *num + len);
	p = (char *)&ret[*num];
	i = 0;
	while ((dirent = readdir(dir)) != NULL) {
		if (strchr(dirent->d_name, '.'))
			continue;
		ret[i] = p;
		strcpy(p, dirent->d_name);
		p += strlen(p) + 1;
		i++;
	}
	closedir(dir);

	return ret;
}

static char *filename_to_data(const char *filename)
{
	struct stat st;

	if (lstat(filename, &st) == 0 && S_ISDIR(st.st_mode))
		return talloc_asprintf(filename, "%s/.DATA", filename);
	return (char *)filename;
}

static void *file_read(struct file_ops_info *info,
		       const char *path, unsigned int *len)
{
	void *ret;
	char *filename = filename_to_data(path_to_name(info, path));
	unsigned long size;

	ret = grab_file(filename, &size);
	/* Directory exists, .DATA doesn't. */
	if (!ret && errno == ENOENT && strends(filename, ".DATA")) {
		ret = strdup("");
		size = 0;
	}
	*len = size;
	return ret;
}

static struct xs_permissions *file_get_perms(struct file_ops_info *info,
					     const char *path,
					     unsigned int *num)
{
	void *perms;
	struct xs_permissions *ret;
	char *filename = path_to_name(info, path);
	char *permfile;
	unsigned long size;
	struct stat st;

	if (lstat(filename, &st) != 0)
		return NULL;

	if (S_ISDIR(st.st_mode)) 
		permfile = talloc_asprintf(path, "%s/.perms", filename);
	else
		permfile = talloc_asprintf(path, "%s.perms", filename);

	perms = grab_file(permfile, &size);
	if (!perms)
		barf("Grabbing permissions for %s", permfile);
	*num = xs_count_strings(perms, size);

	ret = new_array(struct xs_permissions, *num);
	if (!xs_strings_to_perms(ret, *num, perms))
		barf("Reading permissions from %s", permfile);
	release_file(perms, size);
	return ret;
}

static void do_command(const char *cmd)
{
	int ret;

	ret = system(cmd);
	if (ret == -1 || !WIFEXITED(ret) || WEXITSTATUS(ret) != 0)
		barf_perror("Failed '%s': %i", cmd, ret);
}

static void init_perms(const char *filename)
{
	struct stat st;
	char *permfile, *command;

	if (lstat(filename, &st) != 0)
		barf_perror("Failed to stat %s", filename);

	if (S_ISDIR(st.st_mode)) 
		permfile = talloc_asprintf(filename, "%s/.perms", filename);
	else
		permfile = talloc_asprintf(filename, "%s.perms", filename);

	/* Leave permfile if it already exists. */
	if (lstat(permfile, &st) == 0)
		return;

	/* Copy permissions from parent */
	command = talloc_asprintf(filename, "cp %.*s/.perms %s",
				  (int)(strrchr(filename, '/') - filename),
				  filename, permfile);
	do_command(command);
}	

static bool file_set_perms(struct file_ops_info *info,
			   const char *path,
			   struct xs_permissions *perms,
			   unsigned int num)
{
	unsigned int i;
	char *filename = path_to_name(info, path);
	char *permfile;
	int fd;
	struct stat st;

	if (num < 1) {
		errno = EINVAL;
		return false;
	}

	/* Check non-perm file exists/ */
	if (lstat(filename, &st) != 0)
		return false;

	if (S_ISDIR(st.st_mode)) 
		permfile = talloc_asprintf(path, "%s/.perms", filename);
	else
		permfile = talloc_asprintf(path, "%s.perms", filename);

	fd = open(permfile, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (fd < 0)
		return false;

	for (i = 0; i < num; i++) {
		char buffer[100];

		if (!xs_perm_to_string(&perms[i], buffer)) {
			int saved_errno = errno;
			close(fd);
			errno = saved_errno;
			return false;
		}
		if (write(fd, buffer, strlen(buffer) + 1)
		    != (int)strlen(buffer) + 1)
			barf_perror("Failed to write perm");
	}
	close(fd);
	return true;
}

static char *parent_filename(const char *name)
{
	char *slash = strrchr(name + 1, '/');
	if (!slash)
		return talloc_strdup(name, "/");
	return talloc_asprintf(name, "%.*s", (int)(slash-name), name);
}

static void make_dirs(const char *filename)
{
	struct stat st;

	if (lstat(filename, &st) == 0 && S_ISREG(st.st_mode))
		convert_to_dir(filename);

	if (mkdir(filename, 0700) == 0) {
		init_perms(filename);
		return;
	}
	if (errno == EEXIST)
		return;

	make_dirs(parent_filename(filename));
	if (mkdir(filename, 0700) != 0)
		barf_perror("Failed to mkdir %s", filename);
	init_perms(filename);
}

static bool file_write(struct file_ops_info *info,
		       const char *path, const void *data,
		       unsigned int len)
{
	char *filename = filename_to_data(path_to_name(info, path));
	int fd;

	make_dirs(parent_filename(filename));
	fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0600);
	if (fd < 0)
		return false;

	if (write(fd, data, len) != (int)len)
		barf_perror("Bad write to %s", filename);

	init_perms(filename);
	close(fd);
	return true;
}

static bool file_mkdir(struct file_ops_info *info, const char *path)
{
	char *dirname = path_to_name(info, path);

	make_dirs(parent_filename(dirname));
	if (mkdir(dirname, 0700) != 0)
		return (errno == EEXIST);

	init_perms(dirname);
	return true;
}

static bool file_rm(struct file_ops_info *info, const char *path)
{
	char *filename = path_to_name(info, path);
	struct stat st;

	if (lstat(filename, &st) != 0) {
		if (lstat(parent_filename(filename), &st) != 0)
			return false;
		return true;
	}

	if (streq(path, "/")) {
		errno = EINVAL;
		return false;
	}

	do_command(talloc_asprintf(path, "rm -f %s.perms; rm -r %s", 
				   filename, filename));
	return true;
}

static bool file_transaction_start(struct file_ops_info *info)
{
	char *cmd;

	if (info->transact_base) {
		errno = EBUSY;
		return false;
	}

	info->transact_base = talloc_asprintf(NULL, "%s.transact", info->base);
	cmd = talloc_asprintf(NULL, "cp -r %s %s",
			      info->base, info->transact_base);
	do_command(cmd);
	talloc_free(cmd);
	return true;
}

static bool file_transaction_end(struct file_ops_info *info, bool abort)
{
	char *old, *cmd;

	if (!info->transact_base) {
		errno = ENOENT;
		return false;
	}

	if (abort) {
		cmd = talloc_asprintf(NULL, "rm -rf %s", info->transact_base);
		do_command(cmd);
		goto success;
	}

	old = talloc_asprintf(NULL, "rm -rf %s", info->base);
	do_command(old);
	talloc_free(old);

	cmd = talloc_asprintf(NULL, "mv %s %s",
			      info->transact_base, info->base);
	do_command(cmd);

success:
	talloc_free(cmd);
	talloc_free(info->transact_base);
	info->transact_base = NULL;
	return true;
}

static struct file_ops_info *file_handle(const char *dir)
{
	struct file_ops_info *info = talloc(NULL, struct file_ops_info);

	info->base = dir;
	info->transact_base = NULL;
	return info;
}

static void file_close(struct file_ops_info *handle)
{
	talloc_free(handle);
}

static struct xs_handle *xs_handle(const char *dir __attribute__((unused)))
{
	struct xs_handle *h;

	h = xs_daemon_open();
	if (!h)
		barf_perror("Connecting to xs daemon");
	return h;
}

static void xs_close(struct xs_handle *handle)
{
	xs_daemon_close(handle);
}

struct ops file_ops = {
	.name = "FILE",
	.dir = (void *)file_directory,
	.read = (void *)file_read,
	.write = (void *)file_write,
	.mkdir = (void *)file_mkdir,
	.rm = (void *)file_rm,
	.get_perms = (void *)file_get_perms,
	.set_perms = (void *)file_set_perms,
	.transaction_start = (void *)file_transaction_start,
	.transaction_end = (void *)file_transaction_end,
	.handle = (void *)file_handle,
	.close = (void *)file_close,
};

struct ops xs_ops = {
	.name = "XS",
	.dir = (void *)xs_directory,
	.read = (void *)xs_read,
	.write = (void *)xs_write,
	.mkdir = (void *)xs_mkdir,
	.rm = (void *)xs_rm,
	.get_perms = (void *)xs_get_permissions,
	.set_perms = (void *)xs_set_permissions,
	.transaction_start = (void *)xs_transaction_start,
	.transaction_end = (void *)xs_transaction_end,
	.handle = (void *)xs_handle,
	.close = (void *)xs_close,
};

static int strptrcmp(const void *a, const void *b)
{
	return strcmp(*(char **)a, *(char **)b);
}

static void sort_dir(char **dir, unsigned int num)
{
	qsort(dir, num, sizeof(char *), strptrcmp);
}

static char *dump_dir(struct ops *ops,
		      void *h,
		      const char *node,
		      char **dir,
		      unsigned int numdirs,
		      unsigned int depth)
{
	char *ret = talloc_strdup(node, "");
	unsigned int i;
	char spacing[depth+1];

	memset(spacing, ' ', depth);
	spacing[depth] = '\0';

	sort_dir(dir, numdirs);

	for (i = 0; i < numdirs; i++) {
		struct xs_permissions *perms;
		unsigned int j, numperms;
		unsigned int len;
		char *contents;
		unsigned int subnum;
		char **subdirs;
		char *subret;
		char *subnode = talloc_asprintf(node, "%s/%s", node, dir[i]);

		perms = ops->get_perms(h, subnode, &numperms);
		if (!perms)
			return NULL;
		ret = talloc_asprintf_append(ret, "%s%s: ", spacing, dir[i]);
		for (j = 0; j < numperms; j++) {
			char buffer[100];
			if (!xs_perm_to_string(&perms[j], buffer))
				barf("perm to string");
			ret = talloc_asprintf_append(ret, "%s ", buffer);
		}
		free(perms);
		ret = talloc_asprintf_append(ret, "\n");

		/* Even directories can have contents. */
		contents = ops->read(h, subnode, &len);
		if (!contents) {
			if (errno != EISDIR)
				return NULL;
		} else {
			ret = talloc_asprintf_append(ret, " %s(%.*s)\n",
						     spacing, len, contents);
			free(contents);
		}			

		/* Every node is a directory. */
		subdirs = ops->dir(h, subnode, &subnum);
		if (!subdirs)
			return NULL;
		subret = dump_dir(ops, h, subnode, subdirs, subnum, depth+1);
		if (!subret)
			return NULL;
		ret = talloc_asprintf_append(ret, "%s", subret);
		free(subdirs);
	}
	return ret;
}

static char *dump(struct ops *ops, void *h)
{
	char **subdirs;
	unsigned int subnum;
	char *ret = NULL, *root = talloc_strdup(NULL, "/");

	subdirs = ops->dir(h, root, &subnum);
	if (subdirs) {
		ret = dump_dir(ops, h, talloc_strdup(root, ""), subdirs,
			       subnum, 0);
		free(subdirs);
		if (ret)
			talloc_steal(NULL, ret);
	}
	talloc_free(root);
	return ret;
}

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose.  It has no warranty.
 *
 * Copyright (C) 2003 David S. Miller (davem@redhat.com)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are surely my fault.  -DaveM
 */

/* NOTE: Arguments are modified. */
#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO	0x9e3779b9

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
static inline u32 jhash(const void *key, u32 length, u32 initval)
{
	u32 a, b, c, len;
	const u8 *k = key;

	len = length;
	a = b = JHASH_GOLDEN_RATIO;
	c = initval;

	while (len >= 12) {
		a += (k[0] +((u32)k[1]<<8) +((u32)k[2]<<16) +((u32)k[3]<<24));
		b += (k[4] +((u32)k[5]<<8) +((u32)k[6]<<16) +((u32)k[7]<<24));
		c += (k[8] +((u32)k[9]<<8) +((u32)k[10]<<16)+((u32)k[11]<<24));

		__jhash_mix(a,b,c);

		k += 12;
		len -= 12;
	}

	c += length;
	switch (len) {
	case 11: c += ((u32)k[10]<<24);
	case 10: c += ((u32)k[9]<<16);
	case 9 : c += ((u32)k[8]<<8);
	case 8 : b += ((u32)k[7]<<24);
	case 7 : b += ((u32)k[6]<<16);
	case 6 : b += ((u32)k[5]<<8);
	case 5 : b += k[4];
	case 4 : a += ((u32)k[3]<<24);
	case 3 : a += ((u32)k[2]<<16);
	case 2 : a += ((u32)k[1]<<8);
	case 1 : a += k[0];
	};

	__jhash_mix(a,b,c);

	return c;
}

/* A special optimized version that handles 1 or more of u32s.
 * The length parameter here is the number of u32s in the key.
 */
static inline u32 jhash2(u32 *k, u32 length, u32 initval)
{
	u32 a, b, c, len;

	a = b = JHASH_GOLDEN_RATIO;
	c = initval;
	len = length;

	while (len >= 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		__jhash_mix(a, b, c);
		k += 3; len -= 3;
	}

	c += length * 4;

	switch (len) {
	case 2 : b += k[1];
	case 1 : a += k[0];
	};

	__jhash_mix(a,b,c);

	return c;
}


/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *       done at the end is not done here.
 */
static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_GOLDEN_RATIO;
	b += JHASH_GOLDEN_RATIO;
	c += initval;

	__jhash_mix(a, b, c);

	return c;
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
	return jhash_3words(a, b, 0, initval);
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
	return jhash_3words(a, 0, 0, initval);
}

static unsigned int get_randomness(int *state)
{
	return jhash_1word((*state)++, *state * 1103515243);
}

static char *random_path(int *state)
{
	unsigned int i;
	char *ret = NULL;

	if (get_randomness(state) % 20 == 0)
		return talloc_strdup(NULL, "/");

	for (i = 0; i < 1 || (get_randomness(state) % 2); i++) {
		ret = talloc_asprintf_append(ret, "/%i", 
					     get_randomness(state) % 15);
	}
	return ret;
}

static char *bool_to_errstring(bool result)
{
	if (result)
		return talloc_strdup(NULL, "OK");

	/* Real daemon can never return this. */
	if (errno == ENOTDIR)
		errno = ENOENT;
	return talloc_asprintf(NULL, "FAILED:%s", strerror(errno));
}

static char *linearize_dir(char **dir, unsigned int *num)
{
	char *result = NULL;
	unsigned int i;

	if (!dir)
		return bool_to_errstring(false);

	if (!*num) {
		free(dir);
		return talloc_strdup(NULL, "");
	}

	sort_dir(dir, *num);
	for (i = 0; i < *num; i++)
		result = talloc_asprintf_append(result, "%s\n", dir[i]);
	free(dir);
	return result;
}

static char *linearize_read(char *read, unsigned int *size)
{
	char *ret;

	if (!read)
		return bool_to_errstring(false);

	ret = talloc_asprintf(NULL, "%i:%.*s", *size, *size, read);
	free(read);
	return ret;
}

static char *linearize_perms(struct xs_permissions *perms, unsigned int *size)
{
	char *ret = NULL;
	unsigned int i;

	if (!perms)
		return bool_to_errstring(false);

	for (i = 0; i < *size; i++)
		ret = talloc_asprintf_append(ret, "(%u %u)",
					     perms[i].id, perms[i].perms);

	free(perms);
	return ret;
}

/* Do the next operation, return the results. */
static char *do_next_op(struct ops *ops, void *h, int state, bool verbose)
{
	char *name;
	unsigned int num;
	char *ret;

	if (verbose)
		printf("State %i: ", state);

	name = random_path(&state);
	switch (get_randomness(&state) % 9) {
	case 0:
		if (verbose)
			printf("DIR %s\n", name);
		ret = linearize_dir(ops->dir(h, name, &num), &num);
		break;
	case 1:
		if (verbose)
			printf("READ %s\n", name);
		ret = linearize_read(ops->read(h, name, &num), &num);
		break;
	case 2: {
		char *contents = talloc_asprintf(NULL, "%i",
						 get_randomness(&state));
		unsigned int len = get_randomness(&state)%(strlen(contents)+1);
		if (verbose)
			printf("WRITE %s %.*s\n", name, len, contents);
		ret = bool_to_errstring(ops->write(h, name, contents, len));
		talloc_steal(ret, contents);
		break;
	}
	case 3:
		if (verbose)
			printf("MKDIR %s\n", name);
		ret = bool_to_errstring(ops->mkdir(h, name));
		break;
	case 4:
		if (verbose)
			printf("RM %s\n", name);
		ret = bool_to_errstring(ops->rm(h, name));
		break;
	case 5:
		if (verbose)
			printf("GETPERMS %s\n", name);
		ret = linearize_perms(ops->get_perms(h, name, &num),
				      &num);
		break;
	case 6: {
		unsigned int i, num = get_randomness(&state)%8;
		struct xs_permissions perms[num];

		if (verbose)
			printf("SETPERMS %s: ", name);
		for (i = 0; i < num; i++) {
			perms[i].id = get_randomness(&state)%8;
			perms[i].perms = get_randomness(&state)%4;
			if (verbose)
				printf("%i%c ", perms[i].id,
				       perms[i].perms == XS_PERM_WRITE ? 'W'
				       : perms[i].perms == XS_PERM_READ ? 'R'
				       : perms[i].perms == 
				       (XS_PERM_READ|XS_PERM_WRITE) ? 'B'
				       : 'N');
		}
		if (verbose)
			printf("\n");
		ret = bool_to_errstring(ops->set_perms(h, name, perms,
						       num));
		break;
	}
	case 7: {
		if (verbose)
			printf("START %s\n", name);
		ret = bool_to_errstring(ops->transaction_start(h));
		if (streq(ret, "OK")) {
			talloc_free(ret);
			ret = talloc_asprintf(NULL, "OK:START-TRANSACT");
		}

		break;
	}
	case 8: {
		bool abort = (get_randomness(&state) % 2);

		if (verbose)
			printf("STOP %s\n", abort ? "ABORT" : "COMMIT");
		ret = bool_to_errstring(ops->transaction_end(h, abort));
		if (streq(ret, "OK")) {
			talloc_free(ret);
			ret = talloc_strdup(NULL, "OK:STOP-TRANSACT");
		}
		break;
	}
	default:
		barf("Impossible randomness");
	}

	talloc_steal(ret, name);
	return ret;
}

static int daemon_pid;

static void cleanup_xs_ops(void)
{
	char *cmd;

	if (daemon_pid) {
		kill(daemon_pid, SIGTERM);
		waitpid(daemon_pid, NULL, 0);
		daemon_pid = 0;
	}
	
	cmd = talloc_asprintf(NULL, "rm -rf testsuite/tmp/*");
	do_command(cmd);
	talloc_free(cmd);
}

static void cleanup_file_ops(const char *dir)
{
	char *cmd;

	cmd = talloc_asprintf(NULL, "rm -rf %s %s.transact", dir, dir);
	do_command(cmd);
	talloc_free(cmd);
}

static void cleanup(const char *dir)
{
	cleanup_xs_ops();
	cleanup_file_ops(dir);
}

static void setup_file_ops(const char *dir)
{
	struct xs_permissions perm = { .id = 0, .perms = XS_PERM_READ };
	struct file_ops_info *h = file_handle(dir);
	if (mkdir(dir, 0700) != 0)
		barf_perror("Creating directory %s", dir);
	if (mkdir(talloc_asprintf(h, "%s/tool", dir), 0700) != 0)
		barf_perror("Creating directory %s/tool", dir);
	if (!file_set_perms(h, talloc_strdup(h, "/"), &perm, 1))
		barf_perror("Setting root perms in %s", dir);
	if (!file_set_perms(h, talloc_strdup(h, "/tool"), &perm, 1))
		barf_perror("Setting root perms in %s/tool", dir);
	file_close(h);
}

static void setup_xs_ops(void)
{
	int fds[2];

	/* Start daemon. */
	pipe(fds);
	if ((daemon_pid = fork())) {
		/* Child writes PID when its ready: we wait for that. */
		char buffer[20];
		close(fds[1]);
		if (read(fds[0], buffer, sizeof(buffer)) < 0)
			barf("Failed to summon daemon");
		close(fds[0]);
	} else {
		dup2(fds[1], STDOUT_FILENO);
		close(fds[0]);
#if 1
		execlp("valgrind", "valgrind", "-q", "--suppressions=testsuite/vg-suppressions", "xenstored_test", "--output-pid",
		       "--no-fork", NULL);
#else
		execlp("./xenstored_test", "xenstored_test", "--output-pid",
		       "--no-fork", NULL);
#endif
		exit(1);
	}
}

static void setup(const char *dir)
{
	setup_file_ops(dir);
	setup_xs_ops();
};

struct simple_data
{
	unsigned int seed;
	bool print_progress;
	bool fast;
	struct ops *ops;
	const char *dir;
};

/* Just a random test.  Don't care about results, just that it doesn't
 * go boom. */
static unsigned int try_simple(const bool *trymap,
			       unsigned int number,
			       bool verbose,
			       void *_data)
{
	unsigned int i, print;
	void *h;
	char *snapshot = NULL;
	struct simple_data *data = _data;

	if (data->ops == &xs_ops) {
		cleanup_xs_ops();
		setup_xs_ops();
	} else {
		cleanup_file_ops(data->dir);
		setup_file_ops(data->dir);
	}
	h = data->ops->handle(data->dir);

	print = number / 76;
	if (!print)
		print = 1;

	for (i = 0; i < number; i++) {
		char *ret;

		if (data->print_progress) {
			if (i % print == 0) {
				printf(".");
				fflush(stdout);
			}
		}

		if (trymap && !trymap[i])
			continue;

		ret = do_next_op(data->ops, h, i + data->seed, verbose);
		if (verbose)
			printf("-> %.*s\n",
			       (int)(strchr(ret, '\n') - ret), ret);
		if (streq(ret, "FAILED:Bad file descriptor"))
			goto out;
		if (kill(daemon_pid, 0) != 0)
			goto out;

		if (!data->fast) {
			if (streq(ret, "OK:START-TRANSACT")) {
				void *pre = data->ops->handle(data->dir);

				snapshot = dump(data->ops, pre);
				if (!snapshot)
					goto out;
				data->ops->close(pre);
			} else if (streq(ret, "OK:STOP-TRANSACT")) {
				talloc_free(snapshot);
				snapshot = NULL;
			}
		}

		talloc_free(ret);

		if (snapshot) {
			void *pre = data->ops->handle(data->dir);
			char *contents;

			contents = dump(data->ops, pre);
			if (!contents)
				goto out;

			if (!streq(contents, snapshot))
				goto out;

			talloc_free(contents);
			data->ops->close(pre);
		}
	}
out:
	data->ops->close(h);	
	return i;
}

/* Binary elimination: try eliminating all of them, then reduce. */
static void reduce(bool *map,
		   unsigned int number,
		   unsigned int try_start, unsigned int try_num,
		   unsigned int (*try)(const bool *map,
				       unsigned int number,
				       bool verbose,
				       void *),
		   void *data)
{
	bool newmap[number];

	if (try_num == 0)
		return;

	/* Try skipping everything between start and end.  */
	memcpy(newmap, map, sizeof(newmap));
	memset(newmap + try_start, 0, try_num * sizeof(bool));

	/* We want the *same* failure: must fail at "number-1". */
	if (try(newmap, number, false, data) == number - 1) {
		memset(map + try_start, 0, try_num * sizeof(bool));
		return;
	}

	if (try_num == 1)
		return;

	/* Try each half... */
	reduce(map, number, try_start, try_num/2, try, data);
	reduce(map, number, try_start + try_num/2, try_num - try_num/2,
	       try, data);
}

static void reduce_problem(unsigned int failed,
			   unsigned int (*try)(const bool *map,
					       unsigned int number,
					       bool verbose,
					       void *data),
			   void *data)
{
	bool map[failed];

	memset(map, 1, sizeof(map));
	reduce(map, failed, 0, failed-1, try, data);

	printf("Cut down:\n");
	if (try(map, failed, true, data) != failed - 1) {
		printf("Except, that didn't actually fail.  Bugger!");
		exit(2);
	}
	exit(1);
}

/* Just a random test.  Don't care about results, just that it doesn't
 * go boom. */
static void simple_test(const char *dir,
			unsigned int iters, unsigned int seed,
			bool fast, bool verbose)
{
	struct simple_data data;
	unsigned int try;

	data.seed = seed;
	data.print_progress = !verbose;
	data.fast = fast;
	data.ops = &xs_ops;
	data.dir = dir;

	try = try_simple(NULL, iters, verbose, &data);
	if (try == iters) {
		cleanup_xs_ops();
		exit(0);
	}
	printf("Failed on iteration %u of seed %u\n", try + 1, seed);
	data.print_progress = false;
	reduce_problem(try + 1, try_simple, &data);
}

static bool ops_equal(struct ops *a, void *ah,
		      struct ops *b, void *bh,
		      const char *node,
		      struct ops **fail)
{
	char **dira = NULL, **dirb = NULL;
	char *dataa = NULL, *datab = NULL;
	unsigned int i, numa, numb, lena, lenb;
	struct xs_permissions *permsa = NULL, *permsb = NULL;
	unsigned int numpermsa, numpermsb;
	char *nodename;
	bool ret = false;

	/* Ignore tool/ dir. */
	if (streq(node, "/tool"))
		return true;

	/* FILE backend expects talloc'ed pointer. */
	nodename = talloc_strdup(NULL, node);
	permsa = a->get_perms(ah, nodename, &numpermsa);
	if (!permsa) {
		*fail = a;
		goto out;
	}
	permsb = b->get_perms(bh, nodename, &numpermsb);
	if (!permsb) {
		*fail = b;
		goto out;
	}
	if (numpermsa != numpermsb)
		goto out;
	for (i = 0; i < numpermsa; i++) {
		if (permsa[i].perms != permsb[i].perms)
			goto out;
		if (permsa[i].id != permsb[i].id)
			goto out;
	}

	/* Non-pure-directory nodes contain data. */
	dataa = a->read(ah, nodename, &lena);
	if (!dataa && errno != EISDIR) {
		*fail = a;
		goto out;
	}
	datab = b->read(bh, nodename, &lenb);
	if (!datab && errno != EISDIR) {
		*fail = b;
		goto out;
	}

	if (dataa) {
		if (!datab)
			goto out;
		if (lena != lenb)
			goto out;

		if (memcmp(dataa, datab, lena) != 0)
			goto out;
	} else
		if (datab)
			goto out;

	/* Everything is a directory. */
	dira = a->dir(ah, nodename, &numa);
	if (!dira) {
		*fail = a;
		goto out;
	}
	dirb = b->dir(bh, nodename, &numb);
	if (!dirb) {
		*fail = b;
		goto out;
	}
	if (numa != numb)
		goto out;
	sort_dir(dira, numa);
	sort_dir(dirb, numb);
	for (i = 0; i < numa; i++) {
		char subnode[strlen(node) + 1 + strlen(dira[i]) + 1];

		if (!streq(dira[i], dirb[i]))
			goto out;

		strcpy(subnode, node);
		if (!streq(node, "/"))
			strcat(subnode, "/");
		strcat(subnode, dira[i]);
		if (!ops_equal(a, ah, b, bh, subnode, fail))
			goto out;
	}

	ret = true;
out:
	free(permsa);
	free(permsb);
	free(dataa);
	free(datab);
	free(dira);
	free(dirb);
	talloc_free(nodename);
	return ret;
}

struct diff_data
{
	unsigned int seed;
	bool print_progress;
	bool fast;
	const char *dir;
};

/* Differential: try both file and xs backend, watch for differences. */
static unsigned int try_diff(const bool *trymap,
			     unsigned int number,
			     bool verbose,
			     void *_data)
{
	void *fileh, *xsh;
	bool transact = false;
	struct ops *fail;
	struct diff_data *data = _data;
	unsigned int i, print;

	cleanup(data->dir);
	setup(data->dir);

	fileh = file_handle(data->dir);
	xsh = xs_handle(data->dir);

	print = number / 76;
	if (!print)
		print = 1;

	for (i = 0; i < number; i++) {
		char *file, *xs;

		if (data->print_progress) {
			if (i % print == 0) {
				printf(".");
				fflush(stdout);
			}
		}
		if (trymap && !trymap[i])
			continue;

		if (verbose)
			printf("FILE: ");

		file = do_next_op(&file_ops, fileh, i+data->seed, verbose);
		if (verbose)
			printf("-> %.*s\n",
			       (int)(strchr(file, '/') - file), file);
		
		if (verbose)
			printf("XS: ");
		xs = do_next_op(&xs_ops, xsh, i+data->seed, verbose);
		if (verbose)
			printf("-> %.*s\n", (int)(strchr(xs, '/') - xs), xs);

		if (!streq(file, xs))
			goto out;

		if (strstarts(file, "OK:START-TRANSACT:"))
			transact = true;
		else if (streq(file, "OK:STOP-TRANSACT"))
			transact = false;

		talloc_free(file);
		talloc_free(xs);

		if (data->fast)
			continue;

		fail = NULL;
		if (!ops_equal(&xs_ops, xsh, &file_ops, fileh, "/", &fail)) {
			if (fail)
				barf("%s failed during test\n", fail->name);
			if (verbose)
				printf("Trees differ:\nXS:%s\nFILE%s\n",
				       dump(&xs_ops, xsh),
				       dump(&file_ops, fileh));
			goto out;
		}

		if (transact) {
			void *fileh_pre = file_handle(data->dir);
			void *xsh_pre = xs_handle(data->dir);

			fail = NULL;
			if (!ops_equal(&xs_ops, xsh_pre, &file_ops, fileh_pre,
				       "/", &fail)) {
				if (fail)
					barf("%s failed during transact\n",
					     fail->name);

				xs_daemon_close(xsh_pre);
				talloc_free(fileh_pre);
				goto out;
			}
			xs_daemon_close(xsh_pre);
			talloc_free(fileh_pre);
		}
	}

	fail = NULL;
	if (data->fast)
		if (!ops_equal(&xs_ops, xsh, &file_ops, fileh, "/", &fail))
			barf("Final result not the same: try without --fast");
out:
	file_ops.close(fileh);	
	xs_ops.close(xsh);	
	return i;
}

/* Differential random test: compare results against file backend. */
static void diff_test(const char *dir,
		      unsigned int iters, unsigned int seed, bool fast, 
		      bool verbose)
{
	struct diff_data data;
	unsigned int try;

	data.seed = seed;
	data.print_progress = !verbose;
	data.fast = fast;
	data.dir = dir;

	try = try_diff(NULL, iters, verbose, &data);
	if (try == iters) {
		cleanup_xs_ops();
		exit(0);
	}
	printf("Failed on iteration %u of seed %u\n", try + 1, seed);
	data.print_progress = false;
	reduce_problem(try + 1, try_diff, &data);
}

struct fail_data
{
	unsigned int seed;
	bool print_progress;
	const char *dir;
};

/* Try xs with inserted failures: every op should either succeed or fail. */
static unsigned int try_fail(const bool *trymap,
			      unsigned int number,
			      bool verbose,
			      void *_data)
{
	unsigned int i, print, tried = 0, aborted = 0;
	struct fail_data *data = _data;
	struct xs_handle *tmpxsh;
	struct file_ops_info *tmpfileh;
	void *fileh, *xsh;
	struct ops *fail;
	char seed[20];

	/* Make sure failures off to shut down. */
	if (daemon_pid)
		kill(daemon_pid, SIGUSR1);
	cleanup(data->dir);
	setup(data->dir);

	fileh = file_handle(data->dir);
	xsh = xs_handle(data->dir);

	print = number / 76;
	if (!print)
		print = 1;

	for (i = 0; i < number; i++) {
		unsigned int limit, failed;
		char *ret;

		/* A few times we fail due to other end OOM. */
		limit = 0;
		while (!xsh) {
			xsh = xs_handle(data->dir);
			if (!xsh && errno == ECONNREFUSED) {
				if (verbose)
					printf("Daemon refused connection\n");
				goto out;
			}
			if (!xsh && limit++ == 5) {
				printf("Daemon failed conn 5 times\n");
				goto out;
			}
		}

		if (data->print_progress) {
			if (i % print == 0) {
				printf(".");
				fflush(stdout);
			}
		}
		if (trymap && !trymap[i])
			continue;

		/* Turn on failure. */
		sprintf(seed, "%i", data->seed + i);
		free(xs_debug_command(xsh, "failtest",seed,strlen(seed)+1));

		if (verbose)
			printf("(%i) seed %s ", i, seed);
		ret = do_next_op(&xs_ops, xsh, i + data->seed, verbose);
		if (streq(ret, "FAILED:Connection reset by peer")
		    || streq(ret, "FAILED:Bad file descriptor")
		    || streq(ret, "FAILED:Broken pipe")) {
			xs_close(xsh);
			xsh = NULL;
			failed = 2;
		} else if (strstarts(ret, "OK"))
			failed = 0;
		else
			failed = 1;

		tried++;
		if (xsh)
			aborted++;

		if (verbose)
			printf("-> %.*s\n",
			       (int)(strchr(ret, '\n') - ret), ret);

		talloc_free(ret);

		/* Turn off failures using signal. */
		if (kill(daemon_pid, SIGUSR1) != 0) {
			if (verbose)
				printf("Failed to signal daemon\n");
			goto out;
		}

		if (failed == 0) {
			/* Succeeded?  Do same thing to file backend
			 * to compare */
		try_applying:
			ret = do_next_op(&file_ops, fileh, i + data->seed,
					 false);
			if (!strstarts(ret, "OK")) {
				if (!verbose)
					printf("File op failed on %i\n",
					       i + data->seed);
				talloc_free(ret);
				goto out;
			}
			talloc_free(ret);
		}

		tmpxsh = xs_handle(data->dir);
		if (!tmpxsh) {
			if (verbose)
				printf("Failed to open signalled daemon");
			goto out;
		}
		tmpfileh = file_handle(data->dir);

		fail = NULL;
		if (!ops_equal(&xs_ops, tmpxsh, &file_ops, tmpfileh, "/",
			       &fail)) {
			if (fail) {
				if (verbose)
					printf("%s failed\n", fail->name);
				goto out;
			}
			/* Maybe op succeeded: try comparing after local op? */
			if (failed == 2) {
				failed = 0;
				if (verbose)
					printf("(Looks like it succeeded)\n");
				xs_close(tmpxsh);
				file_close(tmpfileh);
				goto try_applying;
			}
			if (verbose)
				printf("Trees differ:\nXS:%s\nFILE:%s\n",
				       dump(&xs_ops, tmpxsh),
				       dump(&file_ops, tmpfileh));
			xs_close(tmpxsh);
			file_close(tmpfileh);
			goto out;
		}

		/* If we lost the xs handle, that ended the transaction */
		if (!xsh)
			file_transaction_end(fileh, true);

		xs_close(tmpxsh);
		file_close(tmpfileh);
	}
out:
	if (xsh)
		xs_close(xsh);
	return i;
}

static void fail_test(const char *dir,
		      unsigned int iters, unsigned int seed,
		      bool fast __attribute__((unused)), bool verbose)
{
	struct fail_data data;
	unsigned int try;

	data.seed = seed;
	data.print_progress = !verbose;
	data.dir = dir;

	try = try_fail(NULL, iters, verbose, &data);
	if (try == iters) {
		cleanup_xs_ops();
		exit(0);
	}
	printf("Failed on iteration %u of seed %u\n", try + 1, seed);
	fflush(stdout);
	data.print_progress = false;
	reduce_problem(try + 1, try_fail, &data);
}

int main(int argc, char *argv[])
{
	bool verbose = false;
	bool simple = false;
	bool fast = false;
	bool fail = false;

	if (argv[1] && streq(argv[1], "--fail")) {
		fail = true;
		argv++;
		argc--;
	}

	if (argv[1] && streq(argv[1], "--simple")) {
		simple = true;
		argv++;
		argc--;
	}

	if (argv[1] && streq(argv[1], "--fast")) {
		fast = true;
		argv++;
		argc--;
	}

	if (argv[1] && streq(argv[1], "--verbose")) {
		verbose = true;
		argv++;
		argc--;
	}

	if (argc != 4)
		barf("Usage: xs_random [--fail|--simple] [--fast] [--verbose] <directory> <iterations> <seed>");

	talloc_enable_null_tracking();

	if (fail)
		fail_test(argv[1], atoi(argv[2]), atoi(argv[3]), fast, verbose);
	else if (simple)
		simple_test(argv[1], atoi(argv[2]), atoi(argv[3]), fast, verbose);
	else
		diff_test(argv[1],  atoi(argv[2]), atoi(argv[3]), fast, verbose);
	exit(2);
}

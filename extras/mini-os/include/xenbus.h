#ifndef XENBUS_H__
#define XENBUS_H__

/* Initialize the XenBus system. */
void init_xenbus(void);

/* Read the value associated with a path.  Returns a malloc'd error
   string on failure and sets *value to NULL.  On success, *value is
   set to a malloc'd copy of the value. */
char *xenbus_read(const char *path, char **value);

/* Associates a value with a path.  Returns a malloc'd error string on
   failure. */
char *xenbus_write(const char *path, const char *value);

/* Removes the value associated with a path.  Returns a malloc'd error
   string on failure. */
char *xenbus_rm(const char *path);

/* List the contents of a directory.  Returns a malloc'd error string
   on failure and sets *contents to NULL.  On success, *contents is
   set to a malloc'd array of pointers to malloc'd strings.  The array
   is NULL terminated.  May block. */
char *xenbus_ls(const char *prefix, char ***contents);

/* Reads permissions associated with a path.  Returns a malloc'd error
   string on failure and sets *value to NULL.  On success, *value is
   set to a malloc'd copy of the value. */
char *xenbus_get_perms(const char *path, char **value);

/* Sets the permissions associated with a path.  Returns a malloc'd
   error string on failure. */
char *xenbus_set_perms(const char *path, domid_t dom, char perm);
#endif /* XENBUS_H__ */

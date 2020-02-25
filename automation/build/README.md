Docker Containers
=================

These Docker containers should make it possible to build Xen in
any of the available environments on any system that supports
running Docker. They are organized by distro and tagged with
the version of that distro. They are available from the GitLab
Container Registry under the Xen project at the [registry] and
can be pulled with Docker from the following path:

```
docker pull registry.gitlab.com/xen-project/xen/DISTRO:VERSION
```

To see the list of available containers run `make` in this
directory. You will have to replace the `/` with a `:` to use
them.

Building Xen
------------

From the top level of the source tree it should be possible to
run the following:

```
./automation/scripts/containerize make
```

Which will cause the top level `make` to execute within the default
container, which is currently defined as Debian Stretch. Any arguments
specified to the script will be executed within the container from
the default shell.

There are several environment variables which the containerize script
understands.

- CONTAINER: This overrides the container to use. For CentOS 7.2, use:

  ```
  CONTAINER=centos72 ./automation/scripts/containerize make
  ```

- CONTAINER_PATH: This overrides the path that will be available under the
  `/build` directory in the container, which is the default path.

  ```
  CONTAINER_PATH=/some/other/path ./automation/scripts/containerize ls
  ```

- CONTAINER_ARGS: Allows you to pass extra arguments to Docker
  when starting the container.

- CONTAINER_UID0: This specifies whether root is used inside the container.

- CONTAINER_NO_PULL: If set to 1, the script will not pull from docker hub.
  This is useful when testing container locally.

- XEN_CONFIG_EXPERT: If this is defined in your shell it will be
  automatically passed through to the container.

If your docker host has Linux kernel > 4.11, and you want to use containers
that run old glibc (for example, CentOS 6 or SLES11SP4), you may need to add

```
vsyscall=emulate
```

to the host kernel command line. That enables a legacy interface that is used
by old glibc.


Building a container
--------------------

There is a makefile to make this process easier. You should be
able to run `make DISTRO/VERSION` to have Docker build the container
for you. If you define the `PUSH` environment variable when running the
former `make` command, it will push the container to the [registry] if
you have access to do so and have your Docker logged into the registry.

To login you must run `docker login registry.gitlab.com`. For more
information see the [registry help].

[registry]: https://gitlab.com/xen-project/xen/container_registry
[registry help]: https://gitlab.com/help/user/project/container_registry

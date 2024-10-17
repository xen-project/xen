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

- DOCKED_CMD: Whether to use docker or podman for running the containers.
  podman can be used as a regular user (rootless podman), but for that
  to work, /etc/subuid and /etc/subgid needs to containe the proper
  entries, for such user.
  docker is the default, for running with podman, do:

  ```
  DOCKER_CMD=podman ./automation/scripts/containerize make
  ```

- CONTAINER: This overrides the container to use. For CentOS 7, use:

  ```
  CONTAINER=centos7 ./automation/scripts/containerize make
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
for you.

Xen's dockerfiles use heredocs, which depend on the standardised dockerfile
syntax introduced by [BuiltKit].  This should work by default starting with
docker 23.0, or podman/buildah v1.33.  For older versions of docker, it can be
activated with `DOCKER_BUILDKIT=1` in the environment.

If you define the `PUSH` environment variable when running the
former `make` command, it will push the container to the [registry] if
you have access to do so and have your Docker logged into the registry.

To login you must run `docker login registry.gitlab.com`. For more
information see the [registry help].

This example shows how to refresh a container for a rolling release
such as openSUSE Tumbleweed. Login with the gitlab.com credentials.

```
docker login registry.gitlab.com/xen-project/xen
make -C automation/build opensuse/tumbleweed-x86_64
env CONTAINER_NO_PULL=1 \
  CONTAINER=tumbleweed \
  CONTAINER_ARGS='-e CC=gcc -e CXX=g++ -e debug=y' \
  automation/scripts/containerize automation/scripts/build < /dev/null
make -C automation/build opensuse/tumbleweed-x86_64 PUSH=1
```

[BuildKit]: https://docs.docker.com/build/buildkit/
[registry]: https://gitlab.com/xen-project/xen/container_registry
[registry help]: https://docs.gitlab.com/ee/user/packages/container_registry/


Building/Running container for a different architecture
-------------------------------------------------------

On a x86 host, it is possible to build and run containers for other arch (like
running a container made for Arm) with docker taking care of running the
appropriate software to emulate that arch. For this, simply install the package
`qemu-user-static`, and that's it. Then you can start an Arm container on x86
host like you would start an x86 container.

If that doesn't work, you might find some information on
[multiarch/qemu-user-static](https://github.com/multiarch/qemu-user-static).

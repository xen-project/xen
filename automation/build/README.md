Docker Containers
=================

These Docker containers should make it possible to build Xen in
any of the available environments on any system that supports
running Docker. They are organized by distro and tagged with
the version of that distro. They are available from the GitLab
Container Registry under the Xen project at:

registry.gitlab.com/xen-project/xen/DISTRO:VERSION

To see the list of available containers run `make` in this
directory. You will have to replace the `/` with a `:` to use
them.

Building Xen
------------

From the top level of the source tree it should be possible to
run the following:

docker run --rm -it -v $(PWD):/build -u $(id -u) -e CC=gcc $(CONTAINER) make

There are other modifications that can be made but this will run
the `make` command inside the specified container. It will use your
currently checked out source tree to build with, ensure that file
permissions remain consistent and clean up after itself.

Building a container
--------------------

There is a makefile to make this process easier. You should be
able to run `make DISTRO/VERSION` to have Docker build the container
for you.

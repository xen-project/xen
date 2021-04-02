*************
Live Patching
*************

- Status: **Supported**
- Architecture: x86
- Status: **Tech Preview/Experimental**
- Architecture: ARM
- Component(s): Hypervisor, toolstack

=======
Details
=======

Xen Live Patching has been available as tech preview feature since Xen
4.7 and has now had a couple of releases to stabilize. Xen Live patching
has been used by multiple vendors to fix several real-world security
issues without any severe bugs encountered. Additionally, there are now
tests in OSSTest that test live patching to ensure that no regressions
are introduced.

Based on the amount of testing and usage it has had, we are ready to
declare live patching as a 'Supported' feature on x86.

Live patching is slightly peculiar when it comes to support because it
allows the host administrator to break their system rather easily
depending on the content of the live patch. Because of this, it is
worth detailing the scope of security support:

1) Unprivileged access to live patching operations:
   Live patching operations should only be accessible to privileged
   guests and it shall be treated as a security issue if this is not
   the case.

2) Bugs in the patch-application code such that vulnerabilities exist
   after application:
   If a correct live patch is loaded but it is not applied correctly
   such that it might result in an insecure system (e.g. not all
   functions are patched), it shall be treated as a security issue.

3) Bugs in livepatch-build-tools creating an incorrect live patch that
   results in an insecure host:
   If livepatch-build-tools creates an incorrect live patch that
   results in an insecure host, this shall not be considered a security
   issue. A live patch should be checked to verify that it is valid
   before loading.

4) Loading an incorrect live patch that results in an insecure host or
   host crash:
   If a live patch (whether created using livepatch-build-tools or some
   alternative) is loaded and it results in an insecure host or host
   crash due to the content of the live patch being incorrect or the
   issue being inappropriate to live patch, this is not considered as a
   security issue.

5) Bugs in the live patch parsing code (the ELF loader):
   Bugs in the live patch parsing code such as out-of-bounds reads
   caused by invalid ELF files are not considered to be security issues
   because the it can only be triggered by a privileged domain.

6) Bugs which allow a guest to prevent the application of a livepatch:
   A guest should not be able to prevent the application of a live
   patch. If an unprivileged guest can somehow prevent the application
   of a live patch despite pausing it (xl pause ...), it shall be
   treated as a security issue.

.. note:: It is expected that live patches are tested in a test environment
before being used in production to avoid unexpected issues. In
particular, to avoid the issues described by (3), (4), & (5).

There are also some generic security questions which are worth asking:

1) Is guest->host privilege escalation possible?

The new live patching sysctl subops are only accessible to privileged
domains and this is tested by OSSTest with an XTF test.
There is a caveat -- an incorrect live patch can introduce a guest->host
privilege escalation.

2) Is guest user->guest kernel escalation possible?

No, although an incorrect live patch can introduce a guest user->guest
kernel privilege escalation.

3) Is there any information leakage?

The new live patching sysctl subops are only accessible to privileged
domains so it is not possible for an unprivileged guest to access the
list of loaded live patches. This is tested by OSSTest with an XTF test.
There is a caveat -- an incorrect live patch can introduce an
information leakage.

4) Can a Denial-of-Service be triggered?

There are no known ways that an unprivileged guest can prevent a live
patch from being loaded.
Once again, there is a caveat that an incorrect live patch can introduce
an arbitrary denial of service.

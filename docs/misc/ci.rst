.. SPDX-License-Identifier: CC-BY-4.0

Continuous Integration
======================

Xen Project uses Gitlab-CI for automated testing. Test pipelines for official
staging branches are at
`<https://gitlab.com/xen-project/hardware/xen/-/pipelines>`_. Developers can
schedule test pipelines in their repositories under
`<https://gitlab.com/xen-project/people/>`_.

Hardware runners
****************

Some of the tests are using dedicated hardware runners. Those are not available freely, but the access is granted to individual developers. To get access to them, ask on the ``#XenDevel:matrix.org`` Matrix channel.
After getting access to relevant runners, few extra changes are necessary in settings of the relevant "xen" gitlab project (under your `<https://gitlab.com/xen-project/people/>`_ namespace):

1. Go to Settings -> CI/CD, expand the "Runners" section and enable relevant runners for your project.
2. Expand "Variables" section and add ``QUBES_JOBS=true`` variable for Qubes runners.
3. Go to Settings -> Repository, expand "Branch rules" section and add a rule for protected branches - only those branches will get tests on the hardware runners. It's okay to use a pattern for branch name, and it's okay to allow force push.

Selecting individual tests
**************************

Normally, all build and test jobs are scheduled in a pipeline. When working on a specific patches, it is sometimes useful to run only jobs relevant for the current work - both to save time and to save CI resources. This can be done by seeting ``SELECTED_JOBS_ONLY`` variable when starting the pipeline. The variable holds a regular expression, enclosed with ``/`` that matches jobs to be included. The variable can be set via the gitlab.com web UI or directly when pushing changes to gitlab::

   git push -o ci.variable=SELECTED_JOBS_ONLY="/job1|job2/"

Note if a test job requires some build job, both need to be included in the regex. For example, ``adl-smoke-x86-64-gcc-debug`` requires ``alpine-3.18-gcc-debug``, so to run just this test the command will look like this::

   git push -o ci.variable=SELECTED_JOBS_ONLY="/adl-smoke-x86-64-gcc-debug|alpine-3.18-gcc-debug/"

More details at `<https://docs.gitlab.co.jp/ee/user/project/push_options.html>`_.

Alternatively, irrelevant jobs can be removed from respective yaml files in ``automation/gitlab-ci`` by adding temporary commit on top of the branch.

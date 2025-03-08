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

How to Set Up a New Hardware Runner
***********************************

A hardware runner is a GitLab runner designed to execute Xen tests on real hardware, such as an embedded board or a laptop. The GitLab runner runs on a controller PC, which is connected to the target board used for Xen testing. The controller PC can be any system, from a workstation to a Raspberry Pi.

Steps to Set Up the Controller PC:

1. Install the Docker service
   - Follow the instructions at: [Docker Installation Guide](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository)

2. Install the GitLab Runner service
   - Follow the instructions at: [GitLab Runner Installation Guide](https://docs.gitlab.com/runner/install/linux-repository/#install-gitlab-runner)

3. Register the runner with GitLab
   - Generate a runner token with a specific tag to identify it.
   - Run `gitlab-runner register` and enter the token. Accepting the default settings is sufficient.

These steps are common for setting up any GitLab runner. However, for hardware runners, additional configurations are required to enable the controller PC to:

- Power on and off the target board.
- Connect to the serial interface of the target board.
- Establish an Ethernet connection with the target board.
- Run a TFTP server with a TFTP root directory accessible by GitLab container tests.
  - This allows the test script to place binaries, such as Xen, in the TFTP root before powering on the target board.

To enable the required capabilities, edit the GitLab Runner configuration file located at `/etc/gitlab-runner/config.toml`:

- Map the TFTP boot directory.
- Map the serial device of the target board.

Example Configuration:

    volumes = ["/scratch/gitlab-runner:/scratch/gitlab-runner"]
    devices = ["/dev/ttyUSB0:/dev/ttyUSB0"]

After making these changes, restart the GitLab Runner service:

    gitlab-runner restart

This completes the setup of the hardware runner. The system is now ready for executing Xen tests on real hardware. As an example, to execute tests on an AMD x86 embedded board, we currently use the following script:

    automation/scripts/xilinx-smoke-dom0-x86_64.sh

Other examples are available under automation/scripts, such as
automation/scripts/qubes-x86-64.sh, and at external locations:
`<https://www.qubes-os.org/news/2022/05/05/automated-os-testing-on-physical-laptops>`_,
`<https://github.com/QubesOS/tests-hw-setup/blob/28aa8b86208a54fc2ac986f06c66c92230bf771e/states/gitlab-runner-conf.toml>`_.


Selecting individual tests
**************************

Normally, all build and test jobs are scheduled in a pipeline. When working on a specific patches, it is sometimes useful to run only jobs relevant for the current work - both to save time and to save CI resources. This can be done by seeting ``SELECTED_JOBS_ONLY`` variable when starting the pipeline. The variable holds a regular expression, enclosed with ``/`` that matches jobs to be included. The variable can be set via the gitlab.com web UI or directly when pushing changes to gitlab::

   git push -o ci.variable=SELECTED_JOBS_ONLY="/job1|job2/"

Note if a test job requires some build job, both need to be included in the regex. For example, ``adl-smoke-x86-64-gcc-debug`` requires ``alpine-3.18-gcc-debug``, so to run just this test the command will look like this::

   git push -o ci.variable=SELECTED_JOBS_ONLY="/adl-smoke-x86-64-gcc-debug|alpine-3.18-gcc-debug/"

More details at `<https://docs.gitlab.co.jp/ee/user/project/push_options.html>`_.

Alternatively, irrelevant jobs can be removed from respective yaml files in ``automation/gitlab-ci`` by adding temporary commit on top of the branch.

*******************
Contributing to Xen
*******************

There are many ways to contribute to the Xen Project.

As with any open source project, providing concrete contributions will demonstrate to the project leaders that you are serious about being involved, which helps us separate the people who talk about contributing from the people who actually contribute to the project in a meaningful way. This builds trust in your work, and the people who consistently contribute good work will be given more and more responsibility.

Our goal is to maintain an environment of professionalism, respect, and innovation within Xen Project development.  Please adhere to the following guidelines as you participate in the Xen Project community:

Be professional in all communications. Please avoid flaming, profanity, vulgarity, SHOUTING IN ALL CAPS. Keep personal discussion for the IRC channel. There is never any reason to publicly discuss gender, ethnicity, orientation, lifestyle, or religion in our project.
Stay on topic. If you have a comment that is not relevant to the current discussion, please start a new thread.
Keep it legal. Please use project resources for their intended purpose.
Don’t feed trolls. Every open project attracts unwelcome commentary from individuals trying to get a rise out of someone. When this happens, just ignore them.

=================
Contributing Code 
=================

Because every open source project has slightly different policies for accepting code contributions, here are some specific guidelines for contributing to The Xen Project codebase.

Contributions to the Xen Project codebase follow the conventions as they are known in the Linux Kernel community. In summary, contributions are made through patches that are reviewed by the community.  The project does not require community members to sign contribution or committer agreements. We do require contributors to sign contributions using the sign-off feature of the code repository, following the same approach as the Linux Kernel does (see Developer Certificate Of Origin).

In addition, each Xen Project subproject (also called team) may have its own mailing list, submission guidelines, IRC channel, and culture. Please check the team portal to learn more.

The majority of our projects have some shared conventions:

Before submitting a patch please read the following guides:

- CONTRIBUTING, COPYING, and CODING_STYLE files (these are in most, but not all our our git repositories). 
- Guide to submitting patches via e-mail workflow. Note that XAPI, Mirage OS and XCP-ng follow a standard Github workflow.
- Guide to asking developer questions

You can also ask questions on the `xen-devel@lists.xenproject.org` mailing list or any of the subproject lists and irc channels.

==============================================
Submitting Patches to the Xen Project Codebase
==============================================

Please first check the submission process for the Xen Sub-Project, and send an email to the proper mailing list with [PATCH] as the first word in the subject line.  Each patch should perform a single function.  Patches sent to the mailing lists should be broken up into several email messages of less than 100KB each, with only one patch per email.

Please include a description of why you want the change made (not just the “what”) and why it is important for the team to make this change. Your patch will need to include a signed-off-by tag, author’s name, and other information.

For details about what to include in your patch, you should start with the patch submission documentation.

==========
Escalation
==========

In a project of this size, patches sometimes slip through the cracks. If you submitted a patch to the xen-devel mailing list or bugzilla and did not receive a response within 5 business days, please send an email to xen-devel and in the first line of that email, include this phrase “Patch escalation: no response for x days”.

This is one case where you should “top post” to make sure that the escalation text is read.

======================
Code Security Scanning
======================

The Xen Project is registered with the “Coverity Scan” service which applies Coverity’s static analyser to the Open Source projects. The tool can and does find flaws in the source code which can include security issues. Currently only the Xen Project Hypervisor (i.e. xen.git) is covered by these scans. Triaging and proposing solutions for the flaws found by Coverity is a useful way in which Community members can contribute to the Xen Project.

Members of the community may request access to the Coverity database. However, Coverity requires that you create an account and apply for Xen Project membership by searching for the Xen Project and then requesting to be added to the project. We typically will approve requests within a few days, but reserve rejecting requests from accounts who never engaged with the project (aka never posted to a mailing list) or which look like spam accounts.
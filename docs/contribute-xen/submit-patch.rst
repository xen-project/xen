*************************
Submitting Patches to Xen
*************************

Changes to the Xen Project are submitted to a mailing list either as an individual patch or as a patch series. A patch series is a series of patches that are related and broken into a logical series of individual patches. Patches, if accepted, will turn into commits in the git source tree. However, frequently multiple versions of patches will have to be posted, before the patch is accepted.

Sending the patches to the list
The xen-devel mailing list is moderated for non-subscribers. It is not mandatory to subscribe but it can help avoid this delay. It is possible to subscribe and then disable delivery in the mailman options so as to avoid moderation but not receive list traffic if that is what you would prefer.

=========================
Setting up git send-email
=========================

The most robust way to send files is by using the git send-email command. (If you're using mercurial, please see our submitting_Xen_Patches_-_mercurial).

To do this, first set configure your information:

.. code-block::

    git config --global sendemail.from "YOUR NAME <user@example.org>"
    git config --global sendemail.smtpserver imap.example.org
    git config --global sendemail.smtpuser USER
    # depending on your config you may also set:
    git config --global sendemail.smtpencryption tls

If you don't want to enter password for your SMTP server all the time:

.. code-block::

    git config --global sendemail.smtppass = PASS


Important Settings
~~~~~~~~~~~~~~~~~~

There are a number of settings you may want to set globally or per repository as follows:

# Allows you to drop --thread from git format-patch ...

.. code-block::

    git config --global format.thread true

# Allows you to use -s or --signoff when committing a patch

.. code-block::

    git config --global user.name "YOUR NAME"
    git config --global user.email "<user@example.org>"

Subject Prefix
~~~~~~~~~~~~~~

Patches and patch series are posted to a mailing list: when using the git format-patch command a subject prefix is added to a patch or patch series, which helps disambiguate normal discussions from posted patches and code reviews.

git format-patch creates mails with subject lines such as

.. code-block::

    # Single patch
    [<SUBJECT-PREFIX>] <Title of patch in git>
    # Patch series
    [<SUBJECT-PREFIX> 0/n] <Title of cover letter/patch series>
    [<SUBJECT-PREFIX> 1/n] <Title of 1st patch in git>
    ...
    [<SUBJECT-PREFIX> n/n] <Title of nth patch in git>

Canonical Subject Prefix
~~~~~~~~~~~~~~~~~~~~~~~~
    
As patches for different git repositories can be posted (or CC'ed) to different mailing lists, some conventions have emerged over time which help code reviewers identify which patch is intended for which git tree. We refer to these as canonical subject prefix. The table below shows recommended default Subject Prefixes, which either need to be passed using the `--subject-prefix=<Subject-Prefix>` option when calling git format-patch, or can be set as defaults per git repository as described here

The following table lists common canonical subject prefixes used in the project:

+----------------------+----------------------+----------------------+
| **repo**             | **Subject Prefix**   | **List**             |
+======================+======================+======================+
| git default          | PATCH                |                      |
+----------------------+----------------------+----------------------+
| `xen                 | PATCH                | xen-devel@           |
| .git <http://xenbits | or XEN               |                      |
| .xen.org/gitweb/?p=x | PATCH (recommended)  |                      |
| en.git;a=summary>`__ |                      |                      |
+----------------------+----------------------+----------------------+
| `osstest.git         | OSSTEST PATCH        | xen-devel@           |
|  <http://xenbits.xen |                      |                      |
| .org/gitweb/?p=osste |                      |                      |
| st.git;a=summary>`__ |                      |                      |
+----------------------+----------------------+----------------------+
| `xtf                 | XTF PATCH            | xen-devel@           |
| .git <http://xenbits |                      |                      |
| .xen.org/gitweb/?p=x |                      |                      |
| tf.git;a=summary>`__ |                      |                      |
+----------------------+----------------------+----------------------+
| `xenalyze.git        | XENALYZE PATCH       | xen-devel@           |
| <http://xenbits.xen. |                      |                      |
| org/gitweb/?p=xenaly |                      |                      |
| ze.git;a=summary>`__ |                      |                      |
+----------------------+----------------------+----------------------+
| `livepatch-build-too | L                    | xen-devel@           |
| ls.git <http://xenbi | IVEPATCH-BUILD-TOOLS |                      |
| ts.xen.org/gitweb/?p | PATCH                |                      |
| =livepatch-build-too |                      |                      |
| ls.git;a=summary>`__ |                      |                      |
+----------------------+----------------------+----------------------+
| `mini-os.git         | PATCH                | minios-devel@ but    |
|  <http://xenbits.xen | or MINI-OS           | sometimes xen-devel@ |
| .org/gitweb/?p=mini- | PATCH (recommended)  | is CC'ed             |
| os.git;a=summary>`__ |                      |                      |
+----------------------+----------------------+----------------------+
| `unikraft/un         | UNIKRAFT PATCH       | minios-devel@        |
| ikraft.git <http://x |                      |                      |
| enbits.xen.org/gitwe |                      |                      |
| b/?p=unikraft/unikra |                      |                      |
| ft.git;a=summary>`__ |                      |                      |
+----------------------+----------------------+----------------------+
| `unikra              | UNIKRAFT/<REPO>      | minios-devel@        |
| ft/.../<REPO>.git <h | PATCH                |                      |
| ttp://xenbits.xen.or |                      |                      |
| g/gitweb/?a=project_ |                      |                      |
| list;pf=unikraft>`__ |                      |                      |
+----------------------+----------------------+----------------------+

.. important:: If you do not use a canonical subject prefix some existing and future automated tooling may not work correctly: consider for example a situation in which a patch for livepatch-build-tools.git is sent to xen-devel@ and that this triggers a build test in different environments. In this case, the build test would try and apply the patch to xen.git and might fail in unexpected ways.

Common modifications to the Subject Prefix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In addition, the following modifications to Subject Prefixes are commonly used and can also be used in combination

+----------------------+----------------------+----------------------+
| **Subject Prefix     | **Example**          | **When to use**      |
| Modification**       |                      |                      |
+======================+======================+======================+
| **RFC** ...          | **RFC** XTF PATCH    | RFC means "Request   |
|                      |                      | For Comments"; use   |
|                      |                      | this when sending an |
|                      |                      | experimental patch   |
|                      |                      | for discussion       |
|                      |                      | rather than          |
|                      |                      | application.         |
+----------------------+----------------------+----------------------+
| ... **RESEND**       | XTF PATCH **RESEND** | Typically used if    |
|                      |                      | your patch has not   |
|                      |                      | been reviewed for    |
|                      |                      | some time and you    |
|                      |                      | want to remind       |
|                      |                      | people of the patch  |
+----------------------+----------------------+----------------------+
| .                    | XEN                  | Typically            |
| .. **for-<release>** | PATCH **for-4.13**   | used **after the     |
|                      |                      | master xen.git       |
|                      |                      | branch has been      |
|                      |                      | feature frozen** and |
|                      |                      | you want to          |
|                      |                      | highlight a patch    |
|                      |                      | that is destined for |
|                      |                      | the release which is |
|                      |                      | currently being      |
|                      |                      | developed            |
+----------------------+----------------------+----------------------+
| ... **for-next**     | XEN                  | Typically            |
|                      | PATCH **for-next**   | used **towards the   |
|                      |                      | end of a development |
|                      |                      | cycle** when you     |
|                      |                      | want to highlight a  |
|                      |                      | patch that is        |
|                      |                      | destined for         |
|                      |                      | the **next** release |
+----------------------+----------------------+----------------------+

The `git format-patch` contains the following options to help with these:

* `--rfc` will mark a patch as RFC, but will always lead to RFC PATCH
* `--subject-prefix=<Subject-Prefix>` allows you to set a subject prefix, but will overwrite any defaults you may have set

Changing git defaults to use the Canonical Subject Prefix
---------------------------------------------------------

To change the setting perform

.. code-block:: 

    cd <local-git-tree>
    git config --local format.subjectPrefix "<canonical subject prefix>"

======================
Sending a Patch Series
======================

Step 1: Create Patches using git format-patch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Git format patch allows you to create and save formatted patches in a directory. By default it will create them in the root of your git directory, but you probably want to direct this into a ../patches/feature-version directory (in the examples below ../patches/feature-v2 would contain only v2 of that series). It is also possible to store several versions of a patch, e.g. v1, v2, etc in the same ../patches/feature directory). Let's say the last two commits of your head are part of your series you want to send out. In this case, the command line would look like

.. code-block::

    $ git format-patch --reroll-count=2 --thread --cover-letter -o ../patches/feature-v2 -2

This will create three files, such as

`v2-0000-cover-letter.patch`						
`v2-0002-Patch-to-do-bar.patch`
`v2-0001-Patch-to-do-foo.patch`

.. notes::

    * You will need to edit the subject and body of `v2-0000-cover-letter.patch`.
    * You must always use the `--thread` and `--cover-letter` options. If you omit `--thread`, any automatic tooling and patch checking that is triggered by sending a mail to one of our mailing lists may not work without using this option. You can set `--thread` as a default, as outlined here.
    * `--rfc` and `--subject-prefix=Subject-Prefix`: please read this document before using these options.

Step 2: Use `add_maintainers.pl` (or `get_maintainer.pl`)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Option 1: Use `add_maintainers.pl`
--------------------------------

.. code-block::

    $ ./scripts/add_maintainers.pl -d ../patches/feature-v2

Then follow the instructions (which are essentially Step 3, with correct command line options based on what you pass to add_maintainers.pl). Note that the add_maintainers.pl script works around a limitation of git send-email ... --cc-cmd="./scripts/get_maintainer.pl" ..., which does not automatically update the CC list of your cover letter.

Other useful options include:

* `--reroll-count|-v` (e.g. -v 2): If you store your patches in one directory with different versions in it generated by --reroll-count=2 you want to use this option
* `--patchcc|-p LOCATION`: Inserts CC's into a specific location (see --help ) to `*.patch` files
* `--covercc|-c LOCATION`: Inserts CC's into a specific location (see --help ) to the cover letter
* `--tags|-t`: Adds people who have *-by tags to the mail header (git send-email does not do this itself)
* `--tagscc`: Adds people who have *-by tags to the CC list
* `--arg|-a` (e.g. -a "<argument1 with space>" -a <argument2> ... for arguments you want to pass to `./scripts/get_maintainer.pl`)

Common LOCATION combinations include:

* -p commit: copy CC blocks into the *.patch body (CC's will become part of the commit message)
* -p none -c header: copy CC blocks from *.patch files in the cover letter without modifying *.patch files. This is useful in rerolled patches, where you do not want to modify the CC blocks. -p ccbody behaves similarly, only that any new CCs that may come from an updated MAINTAINERS file or from new files that have been added to *.patch files will be added to *.patch files.
* -p comment -c end: copy CC blocks after the *.patch body (CC's will not be committed) and into the body of the cover letter

Option 2: Use `get_maintainer.pl` Manually
----------------------------------------

Foreach <v2 patchfile> in ../patches/feature (with XXXX > 0000):

- Run: ./scripts/get_maintainer.pl <v2 patchfile>
- Review the e-mail list and prefix each line with Cc: 
- Copy the e-mail CC block into patchfile
- Do anything else you want to do manually

For `v2-0000-cover-letter.patch` take the superset of all the files generated previously and merge, then copy the e-mail CC block into `0000-cover-letter.patch`.

Step 3: Send Patches using git send-email
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Send the patches using:

.. code-block::

    $ git send-email --to xen-devel@lists.xenproject.org ../patches/feature-v2/*.patch

Other useful options include:

--dry-run
--cc if you need to CC additional reviewers (e.g. from within your team)

===========================================================
Submitting Patches against Point Releases, such as Xen 4.10
===========================================================

When you develop against older Xen versions you are likely going to use an outdated version of the MAINTAINERS file. Typically only the files on staging or master are up-to-date. To work around this, use the following slightly modified workflow:

.. code-block:

    $ git format-patch ... -o <patchdir> ...
    $ checkout master
    $ ./scripts/add_maintainers.pl -d <patchdir>
    $ checkout <original branch>
    $ git send-email ... <patchdir>

This ensures that you use the latest set of tools and the latest MAINTAINERS file.

===========================
Sending an Individual Patch
===========================

You can use the same workflow as outlined in the previous section, without generating a cover letter. In this case, the git-format-patch command line in step 1 would look like

.. code-block::

    $ git format-patch --thread -o ../patches/bugfix-v2 -1

This is followed by steps 2 and 3. However, for single patches without a cover letter, using git-send-email alone, is quite a reasonable option. In this case, you can use the following command line, which will get the CC list from the ./scripts/get_maintainer.pl script, which allows you to fold all 3 steps into 1.

.. code-block::

    $ git send-email --to xen-devel@lists.xenproject.org --cc-cmd="./scripts/get_maintainer.pl" -1

Other useful options include:

* --dry-run will go through all the motions of preparing the patchbomb, but instead of sending a mail, will just output the mails it would have sent. Useful for testing.
* --cc if you need to CC additional reviewers (e.g. from within your team)
* --reroll-count=N allows you to change the revision of the patch
* --rfc and --subject-prefix=Subject-Prefix allow you to change the subject prefix: please read this document before using these options

=======================================================================
Using add_maintainers.pl (or get_maintainer.pl) from Outside of xen.git
=======================================================================

You can use `add_maintainers.pl` or `get_maintainer.pl` on any Xen Project git repository with a compatible MAINTAINERS file in the root of its tree. An example is livepatch-build-tools.git. In this case simply replace ./scripts/add_maintainers.pl or ./scripts/get_maintainer.pl with the full path to the script.

# You are in the xen.git sister repository (e.g. livepatch-build-tools)

.. code-block::

    $ git format-patch ... -o <patchdir> ...
    $ $LOCATION-OF-XEN-GIT/scripts/add_maintainers.pl -d <patchdir>
    $ git send-email ... <patchdir>

A minimum template for such a MAINTAINERS file can be found below.

.. code-block::

    This file follows the same conventions as outlined in
    xen.git:MAINTAINERS. Please refer to the file in xen.git
    for more information.

    THE REST
    M:	MAINTAINER1 <maintainer1@email.com>
    M:	MAINTAINER2 <maintainer2@email.com>
    L:	xen-devel@lists.xenproject.org
    S:	Supported
    F:	*
    F:	*/
    V:	xen-maintainers-1

===============================
Reviewing and Resending Patches
===============================

After posting your patches you will hopefully see some response in the form of comments, patch review and eventually commit.

Code Review
~~~~~~~~~~~

The form of the review may often be quite direct and to the point which may be daunting for some people. However bear in mind that detailed criticism of a patch usually means that the reviewer is interested in your patch and wants to see it go in!

Once you have addressed any review you should normally resend the patch. It is normally expected that you address all review comments before reposting. This often means code changes in your patch but could also mean simply responding to the review comments explaining you reasoning or giving reasons why something should be the way it is.

You should also rebase your change against the project's development tree before sending out a new version, such that when it is approved it applies cleanly. The only reason not to do that is if you don't expect it to be approved, and want feedback on what you have. In that case you can do the rebase later.

The relevant command line options in git-format-patch, ./scripts/add_maintainers.pl and git-send-email (if used standalone) for reposting new revisions is `--reroll-count|-v`

Highlight Changes in the New Version
------------------------------------

When resending a patch you should normally include a note of the changes between the current and last version of the patch. Common practice is to include these notes after your Signed-off-by separated by a triple-dash (---). This indicates patch commentary specific to the posting which need not be included in the final changelog (although you should also remember to update the changelog if necessary). You should also include a "V2" (V3, V4 etc) tag in the subject line (if you are using the git send-email command then the `--reroll-count=N` option is helpful here, or for older git versions --subject-prefix='PATCH vN').

Update Tags
-----------

If someone replies to your patch with a tag of the form Acked-by: <Developer>, Reviewed-by:, Tested-by: etc then, assuming you have not significantly reworked the patch, you should include these tags in any reposting after your own Signed-off-by line. This lets people know that the patch has been seen and that someone approves of it and also serves to prevent reviewers wasting time re-reviewing a patch which is not significantly different to last time. The developers with commit access also like to see postings with such tags since it means they are likely to be much easier to deal with and commit.

An example of a new Patch Version
An example of a resend of the example patch from above might be:

.. code-block::

    Subject: [PATCH v2] foobar: Add a new trondle calls

    Add a some new trondle calls to the foobar interface to support
    the new zot feature.

    Signed-off-by: Joe Smith <joe.smith@citrix.com>
    Acked-by: Jane Doe <jane.doe@example.com>

    ---
    Changed since v1:
    * fix coding style
    * be sure to treadle the trondle in the error case.

    diff -r 63531e640828 tools/libxc/Makefile
    --- a/tools/libxc/Makefile	Mon Dec 07 17:01:11 2009 +0000
    +++ b/tools/libxc/Makefile	Mon Dec 21 11:45:00 2009 +0000
    ...

Resending Patches
~~~~~~~~~~~~~~~~~

If you do not get any response to your patch or you got lots of Acked-by's but the patch has not been committed (remember that reviewers and maintainers are busy people too and sometimes things may fall through the cracks) then after some time, perhaps 2-4 weeks (guidelines), you should resend the patch, perhaps including [RESEND] in the subject line to alert people that the last mail was dropped. Before resending you should:

Check that the patch has not been applied to the staging branch, since committers do not always send a notification when they apply a patch. Consider if there is anything you can do to improve the commit message or subject line of your patch to better attract the attention of the relevant people. Remember to include any Acked-by/Reviewed-by which you received in response to the previous post.

How to Know when a Patch has been Committed
-------------------------------------------
Changes committed to Xen Project by the committers are immediately available in the "staging" branch of the main xen.git tree. They are then automatically tested, and if the tests pass the changes are propagated to the "master" branch.

After your Patch is Committed
-----------------------------

If your patch turns out to break something you will be expected to respond promptly to help diagnose and fix the problem. This assumes that you in particular keep an eye on the osstest flight reports sent to xen-devel. If it can't be fixed quickly, your change may be reverted.
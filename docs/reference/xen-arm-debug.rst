************************
Xen Arm Debug Hypercalls
************************

A small set of debug hypercalls are available to help debugging early boot domU issues.

If you are trying to debug early boot code in your guest kernel, either Dom0 or DomU, you might find the Xen on Arm debug hypercalls useful. They are only available to DEBUG builds, i.e., builds with **Debugging Options ---> Developer Checks** enabled.

Simply add one of the following hvc instructions to your code, and Xen will print something on the console for you:

To print the program counter:

.. code-block::

    hvc 0xfffd

To print first byte of register x0:

.. code-block::

    hvc 0xfffe

To prints all registers and stack of the guest:

.. code-block:: 

    hvc 0xffff

To print program counter and a register: e0 prints x0, e1 prints x1, etc.:

.. code-block::

    hvc 0xffe0-0xffef

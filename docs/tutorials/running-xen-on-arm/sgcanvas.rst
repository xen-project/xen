******************************
Building a Model with sgcanvas
******************************

==========================================
Download FastModels and Evaluation License
==========================================

You can download FastModels and an evaluation license from the ARM Info Center. In order to do so you will need to register. Once you have registered you can navigate via the Support drop-down menu, to Resources, Evaluation Products and finally Fast Models. At this point you will be asked to provide a phone number as well as a host MAC address for licensing purposes, you should enter the MAC address of the machine you intend to run the emulator on. Next you should select the Processor model (select Cortex&trade;-A15) and host platform.

At this point your download should begin and you should be shown your license file which you should download and save

============
Installation
============

These instructions are based on the `FE000-KT-00002-r7p0-40rel0.tgz` version of FastModels. (Note, this is an older version of FastModels)

Unpack the tarball and run the setup.bin which is contained. Follow the wizard to install.

.. note:: If your system is a 64 bit Debian Squeeze you need to install the package ia32-libs to be able to run setup.bin.

================
Building a Model
================

We use the example models which ship with FastModels. These are equivalent to the FVP.

If you have access to an AEM license, then you can use `FastModels/FastModelsPortfolio_7.0/examples/RTSM_VE/Build_AEMv7A/RTSM_VE_AEMv7A.sgproj`. If you have a Cortex-A15 evaluation license, use `FastModels/FastModelsPortfolio_7.0/examples/RTSM_VE/Build_Cortex-A15x1/RTSM_VE_Cortex-A15x1.sgproj`.

To start run, follow these steps:

1. Run the following command:

    .. code-block::

        sgcanvas <SGPROJ>

    Using the relevant `.sgproj` file, sgcanvas will start and load the example model.

2. Select your target environment from the **Project, Active Configuration** menu. Select the environment which best matches your host.

3. Click the **Build** button, and then hit **yes** to save your changes.

    sgcanvas will compile your model. The output will be similar to the following output:

    `FastModels/FastModelsPortfolio_7.0/examples/RTSM_VE/Build_Cortex-A15x1/Linux64-Release-GCC-4.1/cadi_system_Linux64-Release-GCC-4.1.so`

    Where, `FastModels/FastModelsPortfolio_7.0/examples/RTSM_VE/Build_Cortex-A15x1` corresponds to the example project which you built and `Linux64-Release-GCC-4.1` corresponds to the Active Configuration which you selected.

.. note:: If your system is a 64 bit Debian Squeeze you need to install the package xutils-dev to be able to compile your model.

===============
Running a Model
===============

A model is run using the `model_shell` tool, or optionally modeldebugger. To run the model, pass the path to the `cadi_system_Linux64-Release-GCC-4.1.so` as the first argument and the kernel to run (e.g. the boot-wrapper) as the second:

.. code-block::

   model_shell FastModels/FastModelsPortfolio_7.0/examples/RTSM_VE/Build_Cortex-A15x1/Linux64-Release-GCC-4.1/cadi_system_Linux64-Release-GCC-4.1.so boot-wrapper.git/linux-system-semi.axf
Welcome
=======

**wolfSSL Python**, a.k.a. ``wolfssl`` is a Python module
that encapsulates `wolfSSL's SSL/TLS library
<https://wolfssl.com/wolfSSL/Products-wolfssl.html>`_.

The **wolfSSL SSL/TLS library** is a lightweight, portable, C-language-based
library targeted at IoT, embedded, and RTOS environments primarily because of
its size, speed, and feature set. It works seamlessly in desktop, enterprise,
and cloud environments as well.

Prerequisites
=============

Linux
-----

During installation via pip this will download the wolfSSL source and compile it, it therefore needs the same prerequisites as the wolfSSL C library. Therefore in Debian / Ubuntu you should do:

.. code-block:: bash

   $ sudo apt install build-essential
   $ sudo apt build-dep libwolfssl-dev

Compiling
=========

The `setup.py` file covers most things you will need to do to build and install from source. As pre-requisites you will need to install either from your OS repository or pip. You'll also need the Python development package for your Python version:

* `cffi`
* `tox`
* `pytest`

To build a source package run `python setup.py sdist`, to build a wheel package run `python setup.py bdist_wheel`. To test the build run `tox`. The `tox` tests rely on Python 3.9 being installed, if you do not have this version we recommend using `pyenv` to install it.

Installation
============

We provide Python wheels (prebuilt binaries) for OSX 64 bits and Linux 64 bits:

.. code-block:: bash

    $ pip install wheel
    $ pip install wolfssl

To build wolfssl-py from source:

.. code-block:: bash

    $ cd wolfssl-py
    $ pip install .

The default pip install clones wolfSSL from GitHub. To build wolfssl-py using a
local installation of the native wolfSSL C library, the USE_LOCAL_WOLFSSL
environment variable should be set.  USE_LOCAL_WOLFSSL can be set to "1" to use
the default library installation location (/usr/local/lib, /usr/local/include),
or to use a custom location it can be set to the install location of your native
wolfSSL library.  For example:

.. code-block:: bash

    # Uses default install location
    $ USE_LOCAL_WOLFSSL=1 pip install .

    # Uses custom install location
    $ USE_LOCAL_WOLFSSL=/tmp/install pip install .

Testing
=======

To run the tox tests in the source code, you'll need ``tox`` and a few other
requirements.

1. Make sure that the testing requirements are installed:

.. code-block:: shell

    sudo -H pip install -r requirements/test.txt


2. Run ``make check``:

.. code-block:: console

    $ make check
    ...
    _________________________________ summary _________________________________
    py3: commands succeeded
    congratulations :)

Support
=======

For support and questions, please email support@wolfssl.com.


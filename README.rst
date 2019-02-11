Welcome
=======

.. image:: https://travis-ci.org/wolfSSL/wolfssl-py.svg?branch=master
    :target: https://travis-ci.org/wolfSSL/wolfssl-py

**wolfSSL Python**, a.k.a. ``wolfssl`` is a Python module
that encapsulates `wolfSSL's SSL/TLS library
<https://wolfssl.com/wolfSSL/Products-wolfssl.html>`_.

The **wolfSSL SSL/TLS library** is a lightweight, portable, C-language-based
library targeted at IoT, embedded, and RTOS environments primarily because of
its size, speed, and feature set. It works seamlessly in desktop, enterprise,
and cloud environments as well.


Installation
============

We provide Python wheels (prebuilt binaries) for OSX 64 bits and Linux 64 bits:

.. code-block:: bash

    $ pip install wolfssl

To build wolfssl-py from source:

.. code-block:: bash

    $ cd wolfssl-py
    $ pip install .

The default pip install clones wolfSSL from GitHub. To build wolfssl-py using a
local installation of the native wolfSSL C library, the USE_LOCAL_WOLFSSL
environment variable should be set.  USE_LOCAL_WOLFSSL can be set to "1" to use
the default library installation location (/usr/local/lib, /usr/local/include),
or to use a custom location it can be set to the install locaiton of your native
wolfSSL library.  For example:

.. code-block:: bash

    # Uses default install location
    $ USE_LOCAL_WOLFSSL=1 pip install .

    # Uses custom install location
    $ USE_LOCAL_WOLFSSL=/tmp/install pip install .

Tests
=====

To run the tests that ship with wolfssl-py, after compiling the library run
one of the following commands:

.. code-block:: bash

    $ pytest
    $ py.test tests

Support
=======

For support and questions, please email support@wolfssl.com.


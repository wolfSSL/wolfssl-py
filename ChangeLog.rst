Current Development
===================

New Features
------------

* wolfSSL builds with ``--disable-oldtls`` now supported

Fixes
-----

* TLS 1.3 support now works correctly and is tested
* Example server was not cleanly closing sockets

wolfSSL-py Release 5.4.0 (July 13, 2022)
========================================

New Features
------------

* Update to wolfSSL 5.4.0 C library
* Add GitHub Actions support and remove Travis CI support

wolfSSL-py Release 5.3.0 (May 13, 2022)
=======================================

New Features
------------

* Update to wolfSSL 5.3.0
* Build completely refactored to be more Python-like and easier to use
* Add support for wolfSSL ctx password callback

Fixes
-----

* Raise error when wolfSSL_write() returns 0
* Update example certs to match main wolfSSL ones

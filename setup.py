#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2006-2019 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

# pylint: disable=wrong-import-position

import os
import sys
from setuptools import setup
from setuptools.command.build_ext import build_ext


# Adding src folder to the include path in order to import from wolfssl
package_dir = os.path.join(os.path.dirname(__file__), "src")
sys.path.insert(0, package_dir)

import wolfssl
from wolfssl._build_wolfssl import build_wolfssl
from wolfssl._build_wolfssl import wolfssl_inc_path, wolfssl_lib_path


# long_description
with open("README.rst") as readme_file:
    long_description = readme_file.read()

with open("LICENSING.rst") as licensing_file:
    long_description = long_description.replace(".. include:: LICENSING.rst\n",
                                                licensing_file.read())

def verify_wolfssl_config():
    # verify wolfSSL library has been configured correctly, so that cffi
    # binding work correctly.

    # open <wolfssl/options.h> header to parse for #define's
    # This will throw a FileNotFoundError if not able to find options.h
    optionsHeaderPath = wolfssl_inc_path() + "/wolfssl/options.h"
    optionsHeader = open(optionsHeaderPath, 'r')
    optionsHeaderStr = optionsHeader.read()
    optionsHeader.close()

    # require HAVE_SNI (--enable-sni) in native lib
    if '#define HAVE_SNI' not in optionsHeaderStr:
        raise RuntimeError("wolfSSL needs to be compiled with --enable-sni")

    # require OPENSSL_EXTRA (--enable-opensslextra) in native lib
    if '#define OPENSSL_EXTRA' not in optionsHeaderStr:
        raise RuntimeError("wolfSSL needs to be compiled with "
            "--enable-opensslextra")

class cffiBuilder(build_ext, object):

    def build_extension(self, ext):
        """ Compile manually the wolfssl-py extension, bypass setuptools
        """

        # if USE_LOCAL_WOLFSSL environment variable has been defined,
        # do not clone and compile wolfSSL from GitHub
        if os.environ.get("USE_LOCAL_WOLFSSL") is None:
            build_wolfssl(wolfssl.__wolfssl_version__)

        verify_wolfssl_config()

        super(cffiBuilder, self).build_extension(ext)

setup(
    name=wolfssl.__title__,
    version=wolfssl.__version__,
    description=wolfssl.__summary__,
    long_description=long_description,
    author=wolfssl.__author__,
    author_email=wolfssl.__email__,
    url=wolfssl.__uri__,
    license=wolfssl.__license__,

    packages=["wolfssl"],
    package_dir={"":package_dir},

    zip_safe=False,
    cffi_modules=["./src/wolfssl/_build_ffi.py:ffi"],

    keywords="wolfssl, wolfcrypt, security, cryptography",
    classifiers=[
        u"License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        u"License :: Other/Proprietary License",
        u"Operating System :: OS Independent",
        u"Programming Language :: Python :: 2.7",
        u"Programming Language :: Python :: 3.4",
        u"Programming Language :: Python :: 3.5",
        u"Programming Language :: Python :: 3.6",
        u"Topic :: Security",
        u"Topic :: Security :: Cryptography",
        u"Topic :: Software Development"
    ],

    setup_requires=["cffi"],
    install_requires=["cffi"],
    test_suite="tests",
    tests_require=["tox", "pytest"],
    cmdclass={"build_ext" : cffiBuilder}
)

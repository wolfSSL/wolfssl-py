#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2006-2020 wolfSSL Inc.
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

import os
import subprocess
import argparse
from contextlib import contextmanager
from distutils.util import get_platform
from wolfssl.__about__ import __wolfssl_version__ as version


def local_path(path):
    """ Return path relative to the root of this project
    """
    current = os.path.dirname(__file__)
    gparent = os.path.dirname(os.path.dirname(current))
    return os.path.abspath(os.path.join(gparent, path))


WOLFSSL_GIT_ADDR = "https://github.com/wolfssl/wolfssl.git"
WOLFSSL_SRC_PATH = local_path("lib/wolfssl/src")


def wolfssl_inc_path():
    wolfssl_path = os.environ.get("USE_LOCAL_WOLFSSL")
    if wolfssl_path is None:
        return local_path("lib/wolfssl/src")
    else:
        if os.path.isdir(wolfssl_path) and os.path.exists(wolfssl_path):
            return wolfssl_path + "/include"
        else:
            return "/usr/local/include"


def wolfssl_lib_path():
    wolfssl_path = os.environ.get("USE_LOCAL_WOLFSSL")
    if wolfssl_path is None:
        return local_path("lib/wolfssl/{}/{}/lib".format(
                          get_platform(), version))
    else:
        if os.path.isdir(wolfssl_path) and os.path.exists(wolfssl_path):
            return wolfssl_path + "/lib"
        else:
            return "/usr/local/lib"


def call(cmd):
    print("Calling: '{}' from working directory {}".format(cmd, os.getcwd()))

    old_env = os.environ["PATH"]
    os.environ["PATH"] = "{}:{}".format(WOLFSSL_SRC_PATH, old_env)
    subprocess.check_call(cmd, shell=True, env=os.environ)
    os.environ["PATH"] = old_env


@contextmanager
def chdir(new_path, mkdir=False):
    old_path = os.getcwd()

    if mkdir:
        try:
            os.mkdir(new_path)
        except OSError:
            pass

    try:
        yield os.chdir(new_path)
    finally:
        os.chdir(old_path)


def clone_wolfssl(ref):
    """ Clone wolfSSL C library repository
    """
    call("git clone --depth=1 --branch={} {} {}".format(
        ref, WOLFSSL_GIT_ADDR, WOLFSSL_SRC_PATH))


def checkout_ref(ref):
    """ Ensure that we have the right version
    """
    with chdir(WOLFSSL_SRC_PATH):
        current = subprocess.check_output(
            ["git", "describe", "--all", "--exact-match"]
        ).strip().decode().split('/')[-1]

        if current != ref:
            tags = subprocess.check_output(
                ["git", "tag"]
            ).strip().decode().split("\n")

            if ref != "master" and ref not in tags:
                call("git fetch --depth=1 origin tag {}".format(ref))

            call("git checkout --force {}".format(ref))

            return True  # rebuild needed

    return False


def ensure_wolfssl_src(ref):
    """ Ensure that wolfssl sources are presents and up-to-date
    """
    if not os.path.isdir(WOLFSSL_SRC_PATH):
        clone_wolfssl(ref)
        return True

    return checkout_ref(ref)


def make_flags(prefix, debug):
    """ Returns compilation flags
    """
    flags = []
    cflags = []

    if get_platform() in ["linux-x86_64", "linux-i686"]:
        cflags.append("-fpic")

    # install location
    flags.append("--prefix={}".format(prefix))

    # lib only
    flags.append("--disable-shared")
    flags.append("--disable-examples")

    # tls 1.3
    flags.append("--enable-tls13")

    # for urllib3 - requires SNI (tlsx), options (openssl compat), peer cert
    flags.append("--enable-tlsx")
    flags.append("--enable-opensslextra")
    cflags.append("-DKEEP_PEER_CERT")

    # for pyOpenSSL
    flags.append("--enable-secure-renegotiation")
    flags.append("--enable-opensslall")
    cflags.append("-DFP_MAX_BITS=8192")
    cflags.append("-DHAVE_EX_DATA")
    cflags.append("-DOPENSSL_COMPATIBLE_DEFAULTS")

    if debug:
        flags.append("--enable-debug")

    # Note: websocket-client test server (echo.websocket.org) only supports
    # TLS 1.2 with TLS_RSA_WITH_AES_128_CBC_SHA
    # If compiling for use with websocket-client, must enable static RSA suites.
    # cflags.append("-DWOLFSSL_STATIC_RSA")

    joined_flags = " ".join(flags)
    joined_cflags = " ".join(cflags)

    return joined_flags + " CFLAGS=\"" + joined_cflags + "\""


def make(configure_flags):
    """ Create a release of wolfSSL C library
    """
    with chdir(WOLFSSL_SRC_PATH):
        call("git clean -fdX")

        try:
            call("./autogen.sh")
        except subprocess.CalledProcessError:
            call("libtoolize")
            call("./autogen.sh")

        call("./configure {}".format(configure_flags))
        call("make")
        call("make install")


def build_wolfssl(ref, debug=False):
    prefix = local_path("lib/wolfssl/{}/{}".format(
        get_platform(), ref))
    libfile = os.path.join(prefix, 'lib/libwolfssl.la')

    rebuild = ensure_wolfssl_src(ref)

    if rebuild or not os.path.isfile(libfile):
        make(make_flags(prefix, debug))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build underlying wolfSSL library (libwolfssl).")
    parser.add_argument("-d", "--debug", action="store_true",
        help="Build libwolfssl with debug enabled.")
    parser.add_argument("-r", '--ref', default="master",
        help="Git ref to check out when cloning wolfSSL.")
    args = parser.parse_args()
    build_wolfssl(args.ref, args.debug)


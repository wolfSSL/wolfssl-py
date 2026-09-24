# -*- coding: utf-8 -*-
#
# test_build_ffi.py
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# pylint: disable=missing-docstring, redefined-outer-name

import os
import re
import shlex

import pytest

import wolfssl

BUILD_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(wolfssl.__file__)), "_build_ffi.py")

# options.h macros of a supported USE_LOCAL_WOLFSSL build. KEEP_PEER_CERT
# is left out: settings.h derives it, so configure output often lacks it.
GOOD_MACROS = ("HAVE_SNI", "OPENSSL_EXTRA", "OPENSSL_ALL")


def _options_h(macros):
    lines = ["#ifndef WOLFSSL_OPTIONS_H", "#define WOLFSSL_OPTIONS_H"]
    for macro in macros:
        lines.append("#undef  %s" % macro)
        lines.append("#define %s" % macro)
    lines.append("#endif")
    return "\n".join(lines) + "\n"


@pytest.fixture
def run_build_script(tmpdir, monkeypatch):
    """Run _build_ffi.py like cffi's setuptools hook does, against a fake
    USE_LOCAL_WOLFSSL prefix that only holds options.h. No C is compiled
    and no wolfSSL is built."""
    pytest.importorskip("distutils.util")

    def run(macros=GOOD_MACROS):
        tmpdir.ensure("include", "wolfssl", "options.h").write(
            _options_h(macros))
        monkeypatch.setenv("USE_LOCAL_WOLFSSL", str(tmpdir))
        namespace = {"__name__": "__cffi__", "__file__": BUILD_SCRIPT}
        with open(BUILD_SCRIPT) as script:
            code = compile(script.read(), BUILD_SCRIPT, "exec")
        exec(code, namespace)
        return namespace
    return run


def _declares(cdef, name):
    return re.search(r"\b%s\s*\(" % name, cdef) is not None


def _without(macros, name):
    return tuple(m for m in macros if m != name)


def _cflags(configure_flags):
    for arg in shlex.split(configure_flags):
        if arg.startswith("CFLAGS="):
            return arg[len("CFLAGS="):].split()
    return []


@pytest.mark.parametrize("platform", [
    "linux-x86_64", "linux-i686", "linux-aarch64", "linux-armv7l",
    "linux-ppc64le", "linux-s390x", "linux-riscv64"])
def test_make_flags_builds_pic_on_linux(run_build_script, platform):
    """The bundled static wolfSSL is linked into the shared extension, so
    it must be position independent on every Linux architecture (F-10706).
    """
    ns = run_build_script()
    ns["get_platform"] = lambda: platform
    flags = ns["make_flags"]("/prefix", False)
    assert "-fPIC" in _cflags(flags), flags


def test_supported_local_build_is_accepted(run_build_script):
    ns = run_build_script()
    assert _declares(ns["ffi_cdef"], "wolfSSL_ctrl")
    assert _declares(ns["ffi_cdef"], "wolfSSL_get_peer_certificate")


def test_local_build_requires_opensslall(run_build_script):
    """wolfSSL_ctrl(), SSL_set_mode() and SSL_OP_NO_TICKET are always bound
    but only exist with OPENSSL_ALL (F-13426).
    """
    with pytest.raises(RuntimeError, match="opensslall"):
        run_build_script(_without(GOOD_MACROS, "OPENSSL_ALL"))


def test_local_build_x509small_is_not_opensslextra(run_build_script):
    """OPENSSL_EXTRA_X509_SMALL alone does not define OPENSSL_EXTRA
    (F-13426).
    """
    with pytest.raises(RuntimeError, match="opensslextra"):
        run_build_script(("HAVE_SNI", "OPENSSL_EXTRA_X509_SMALL"))


def test_local_build_rejects_no_keep_peer_cert(run_build_script):
    """wolfSSL_get_peer_certificate() and wolfSSL_X509_get_subjectCN() are
    always bound but only exist with KEEP_PEER_CERT (F-11777).
    """
    with pytest.raises(RuntimeError, match="KEEP_PEER_CERT"):
        run_build_script(GOOD_MACROS + ("NO_KEEP_PEER_CERT",))


def test_local_build_keep_peer_cert_overrides_no_keep(run_build_script):
    """settings.h never removes an explicit KEEP_PEER_CERT (F-11777)."""
    ns = run_build_script(
        GOOD_MACROS + ("NO_KEEP_PEER_CERT", "KEEP_PEER_CERT"))
    assert _declares(ns["ffi_cdef"], "wolfSSL_get_peer_certificate")

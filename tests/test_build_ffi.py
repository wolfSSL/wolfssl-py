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
import shlex

import pytest

import wolfssl

BUILD_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(wolfssl.__file__)), "_build_ffi.py")

# options.h macros of a supported USE_LOCAL_WOLFSSL build.
GOOD_MACROS = ("HAVE_SNI", "OPENSSL_EXTRA")


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

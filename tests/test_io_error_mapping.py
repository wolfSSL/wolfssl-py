# -*- coding: utf-8 -*-
#
# test_io_error_mapping.py
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

# pylint: disable=missing-docstring, invalid-name, import-error
# pylint: disable=protected-access

"""
These tests exercise the error-code-to-exception mapping in SSLSocket's
read/write/recv_into. wolfSSL_write can return WANT_READ and wolfSSL_read can
return WANT_WRITE during a renegotiation; non-blocking callers rely on these
being surfaced as SSLWantReadError / SSLWantWriteError (matching the stdlib
ssl module) rather than a generic SSLError.

The renegotiation conditions are awkward to force over a real socket, so the
native wolfSSL_read/wolfSSL_write/wolfSSL_get_error functions are stubbed to
return the relevant codes and the Python-level mapping is verified directly.
"""

from types import SimpleNamespace

import pytest
import wolfssl


class _FakeLib:
    """Stand-in for wolfssl._lib that forces a given I/O return / error."""

    def __init__(self, io_ret, err):
        self._io_ret = io_ret
        self._err = err

    def wolfSSL_write(self, ssl, data, length):
        return self._io_ret

    def wolfSSL_read(self, ssl, data, length):
        return self._io_ret

    def wolfSSL_get_error(self, ssl, ret):
        return self._err


def _make_socket():
    """A minimal, non-DTLS SSLSocket that skips __init__/native setup."""
    sock = wolfssl.SSLSocket.__new__(wolfssl.SSLSocket)
    sock.native_object = object()      # non-NULL so _check_closed passes
    sock._connected = True             # so _check_connected is a no-op
    sock._context = SimpleNamespace(protocol=wolfssl.PROTOCOL_TLS)
    # The dummy native_object isn't a real cdata pointer, so make __del__
    # a no-op to avoid wolfSSL_free() choking on it during GC.
    sock._release_native_object = lambda: None
    return sock


def _patch_lib(monkeypatch, io_ret, err):
    monkeypatch.setattr(wolfssl, "_lib", _FakeLib(io_ret, err))


def test_write_want_read_raises_wantread(monkeypatch):
    """F-3905: wolfSSL_write returning WANT_READ -> SSLWantReadError."""
    _patch_lib(monkeypatch, -1, wolfssl._SSL_ERROR_WANT_READ)
    sock = _make_socket()
    with pytest.raises(wolfssl.SSLWantReadError):
        sock.write(b"data")


def test_write_want_write_still_raises_wantwrite(monkeypatch):
    _patch_lib(monkeypatch, -1, wolfssl._SSL_ERROR_WANT_WRITE)
    sock = _make_socket()
    with pytest.raises(wolfssl.SSLWantWriteError):
        sock.write(b"data")


def test_read_want_write_raises_wantwrite(monkeypatch):
    """F-3906: wolfSSL_read returning WANT_WRITE -> SSLWantWriteError."""
    _patch_lib(monkeypatch, -1, wolfssl._SSL_ERROR_WANT_WRITE)
    sock = _make_socket()
    with pytest.raises(wolfssl.SSLWantWriteError):
        sock.read(16)


def test_read_want_read_still_raises_wantread(monkeypatch):
    _patch_lib(monkeypatch, -1, wolfssl._SSL_ERROR_WANT_READ)
    sock = _make_socket()
    with pytest.raises(wolfssl.SSLWantReadError):
        sock.read(16)

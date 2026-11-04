# -*- coding: utf-8 -*-
#
# test_recv_into.py
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

# pylint: disable=missing-docstring, invalid-name, import-error
# pylint: disable=protected-access

"""
F-3483: SSLSocket.recv_into() obtained its destination pointer with
ffi.from_buffer() without require_writable=True, so read-only buffers such
as bytes were accepted and wolfSSL_read() wrote decrypted data straight into
immutable Python objects.
"""

from types import SimpleNamespace

import pytest

import wolfssl

_PAYLOAD = b"decrypted-data"


class _FillLib:
    """Stand-in for _lib whose wolfSSL_read() writes into the destination
    buffer exactly as the native function would."""

    def __init__(self):
        self.calls = 0

    def wolfSSL_read(self, ssl, data, length):
        self.calls += 1
        n = min(length, len(_PAYLOAD))
        wolfssl._ffi.memmove(data, _PAYLOAD[:n], n)
        return n

    def wolfSSL_get_error(self, ssl, ret):  # pragma: no cover
        return 0


def _make_socket(monkeypatch):
    lib = _FillLib()
    monkeypatch.setattr(wolfssl, "_lib", lib)
    sock = wolfssl.SSLSocket.__new__(wolfssl.SSLSocket)
    sock.native_object = object()
    sock._connected = True
    sock._context = SimpleNamespace(protocol=wolfssl.PROTOCOL_TLS)
    sock._release_native_object = lambda: None
    return sock, lib


@pytest.mark.parametrize("make_buffer", [
    lambda: bytes(32),
    lambda: memoryview(bytes(32)),
], ids=["bytes", "readonly-memoryview"])
def test_recv_into_rejects_readonly_buffer(monkeypatch, make_buffer):
    sock, lib = _make_socket(monkeypatch)
    buf = make_buffer()

    with pytest.raises(TypeError):
        sock.recv_into(buf)

    # wolfSSL_read() must never be handed the read-only memory.
    assert lib.calls == 0
    assert bytes(buf) == bytes(32)


@pytest.mark.parametrize("make_buffer", [
    lambda: bytearray(32),
    lambda: memoryview(bytearray(32)),
], ids=["bytearray", "memoryview"])
def test_recv_into_fills_writable_buffer(monkeypatch, make_buffer):
    sock, lib = _make_socket(monkeypatch)
    buf = make_buffer()

    n = sock.recv_into(buf)

    assert lib.calls == 1
    assert n == len(_PAYLOAD)
    assert bytes(buf[:n]) == _PAYLOAD

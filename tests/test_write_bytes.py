# -*- coding: utf-8 -*-
#
# test_write_bytes.py
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
F-5622: SSLSocket.write() ran data through t2b(), which str()-encodes anything
that is not already bytes. Valid bytes-like inputs (bytearray, memoryview)
were therefore serialized as their Python repr ("bytearray(b'...')",
"<memory at 0x...>") instead of their actual contents.
"""

from types import SimpleNamespace

import wolfssl


class _CaptureLib:
    def __init__(self):
        self.written = None

    def wolfSSL_write(self, ssl, data, length):
        self.written = bytes(data[:length])
        return length

    def wolfSSL_get_error(self, ssl, ret):  # pragma: no cover
        return 0


def _make_socket(monkeypatch):
    lib = _CaptureLib()
    monkeypatch.setattr(wolfssl, "_lib", lib)
    sock = wolfssl.SSLSocket.__new__(wolfssl.SSLSocket)
    sock.native_object = object()
    sock._connected = True
    sock._context = SimpleNamespace(protocol=wolfssl.PROTOCOL_TLS)
    sock._release_native_object = lambda: None
    return sock, lib


def test_write_bytes_unchanged(monkeypatch):
    sock, lib = _make_socket(monkeypatch)
    sock.write(b"hello")
    assert lib.written == b"hello"


def test_write_bytearray_sends_contents(monkeypatch):
    sock, lib = _make_socket(monkeypatch)
    sock.write(bytearray(b"hello"))
    assert lib.written == b"hello"


def test_write_memoryview_sends_contents(monkeypatch):
    sock, lib = _make_socket(monkeypatch)
    sock.write(memoryview(b"hello"))
    assert lib.written == b"hello"


def test_write_str_is_utf8_encoded(monkeypatch):
    # Backward compatibility: str is UTF-8 encoded (historical t2b()
    # behavior), not rejected. The \u00e9 escape keeps the source 7-bit
    # ASCII while still exercising a multi-byte UTF-8 encoding.
    sock, lib = _make_socket(monkeypatch)
    sock.write("h\u00e9llo")
    assert lib.written == "h\u00e9llo".encode("utf-8")

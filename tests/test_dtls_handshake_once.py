# -*- coding: utf-8 -*-
#
# test_dtls_handshake_once.py
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
F-4136: for DTLS, write()/read()/recv_into() used to call do_handshake() on
every single call. Once the handshake has completed, re-running it is wasteful
and, on a non-blocking socket, wolfSSL_accept/connect can raise
SSLWantReadError and abort an otherwise valid I/O. The handshake must only be
driven until it completes.
"""

from types import SimpleNamespace

import pytest
import wolfssl


class _OkLib:
    """_lib stub whose I/O calls always succeed."""

    def wolfSSL_write(self, ssl, data, length):
        return length

    def wolfSSL_read(self, ssl, data, length):
        return length

    def wolfSSL_get_error(self, ssl, ret):  # pragma: no cover
        return 0


def _make_dtls_socket(handshake_complete):
    sock = wolfssl.SSLSocket.__new__(wolfssl.SSLSocket)
    sock.native_object = object()
    sock._connected = True
    sock._server_side = True
    sock._context = SimpleNamespace(protocol=wolfssl.PROTOCOL_DTLSv1_2)
    sock._handshake_complete = handshake_complete
    sock._release_native_object = lambda: None
    return sock


@pytest.fixture
def spy_handshake(monkeypatch):
    monkeypatch.setattr(wolfssl, "_lib", _OkLib())
    calls = []

    def _record(sock):
        calls.append(True)
        sock._handshake_complete = True

    return calls, _record


@pytest.mark.parametrize("op", ["write", "read", "recv_into"])
def test_dtls_io_does_not_redrive_completed_handshake(spy_handshake, op):
    calls, record = spy_handshake
    sock = _make_dtls_socket(handshake_complete=True)
    sock.do_handshake = lambda block=False: record(sock)

    if op == "write":
        sock.write(b"payload")
    elif op == "read":
        sock.read(8)
    else:
        sock.recv_into(bytearray(8))

    assert calls == [], "do_handshake() must not run once the handshake is done"


@pytest.mark.parametrize("op", ["write", "read", "recv_into"])
def test_dtls_io_drives_handshake_until_complete(spy_handshake, op):
    calls, record = spy_handshake
    sock = _make_dtls_socket(handshake_complete=False)
    sock.do_handshake = lambda block=False: record(sock)

    if op == "write":
        sock.write(b"payload")
    elif op == "read":
        sock.read(8)
    else:
        sock.recv_into(bytearray(8))

    assert calls == [True], "first DTLS I/O must drive the handshake once"

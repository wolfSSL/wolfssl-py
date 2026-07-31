# -*- coding: utf-8 -*-
#
# test_dtls_server_example.py
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

import os
import sys
import socket

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))
import server as server_example  # noqa: E402


@pytest.fixture
def udp_pair():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("localhost", 0))
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        yield srv, cli, srv.getsockname()
    finally:
        srv.close()
        cli.close()


def test_peek_peer_address_returns_source(udp_pair):
    srv, cli, srv_addr = udp_pair
    cli.bind(("localhost", 0))
    cli.sendto(b"clienthello-payload", srv_addr)

    addr = server_example.peek_peer_address(srv)

    assert addr == cli.getsockname()


def test_peek_peer_address_does_not_consume_datagram(udp_pair):
    """
    Regression test for F-3481: peeking the client's address before the
    DTLS handshake must leave the ClientHello datagram intact. The previous
    example used recvfrom(1), which consumed the datagram and discarded
    everything past the first byte, breaking the handshake.
    """
    srv, cli, srv_addr = udp_pair
    payload = b"X" * 256  # stand-in for a DTLS ClientHello record
    cli.sendto(payload, srv_addr)

    server_example.peek_peer_address(srv)

    # The datagram must still be fully available for wolfSSL_accept().
    srv.settimeout(2)
    data, _ = srv.recvfrom(4096)
    assert data == payload

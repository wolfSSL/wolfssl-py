# -*- coding: utf-8 -*-
#
# test_client.py
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
# pylint: disable=redefined-outer-name

import pytest
import wolfssl
from wolfssltestserver import wolfSSLTestServer
from threading import Thread

HOST = "www.python.org"
PORT = 443
CA_CERTS = "certs/ca-globalsign-r3.pem"


@pytest.fixture(
    params=["wrap_socket", "wrap_socket_with_ca",
            "wrap_socket_from_context", "ssl_socket"])

def secure_socket(request, ssl_provider, tcp_socket):
    sock = None

    if request.param == "wrap_socket":
        sock = ssl_provider.wrap_socket(tcp_socket)

    elif request.param == "wrap_socket_with_ca":
        sock = ssl_provider.wrap_socket(tcp_socket,
                                        cert_reqs=ssl_provider.CERT_REQUIRED,
                                        ca_certs=CA_CERTS)

    elif request.param == "wrap_socket_from_context":
        try:
            ctx = ssl_provider.SSLContext(ssl_provider.PROTOCOL_TLS)
        except AttributeError:
            ctx = ssl_provider.SSLContext(ssl_provider.PROTOCOL_SSLv23)

        ctx.verify_mode = ssl_provider.CERT_REQUIRED
        ctx.load_verify_locations(CA_CERTS)

        sock = ctx.wrap_socket(tcp_socket)

    elif request.param == "ssl_socket":
        sock = ssl_provider.SSLSocket(tcp_socket,
                                      cert_reqs=ssl_provider.CERT_REQUIRED,
                                      ca_certs=CA_CERTS)

    if sock:
        yield sock
        sock.close()

def test_secure_connection(secure_socket):
    secure_socket.connect((HOST, PORT))

    secure_socket.write(b"GET / HTTP/1.1\n\n")
    assert secure_socket.read(4) == b"HTTP"

@pytest.mark.parametrize("ssl_version",
                         [pytest.param((wolfssl.PROTOCOL_TLSv1_1, "TLSv1.1"), id="TLSv1.1"),
                          pytest.param((wolfssl.PROTOCOL_TLSv1_2, "TLSv1.2"), id="TLSv1.2"),
                          pytest.param((wolfssl.PROTOCOL_TLSv1_3, "TLSv1.3"), id="TLSv1.3")])
def test_get_version(ssl_server, ssl_version, tcp_socket):
    protocol = ssl_version[0]
    protocol_name = ssl_version[1]
    try:
        ssl_context = wolfssl.SSLContext(protocol)
    except ValueError:
        pytest.skip("Protocol {} not supported".format(protocol_name))
        return
    secure_socket = ssl_context.wrap_socket(tcp_socket)
    secure_socket.connect(('127.0.0.1', ssl_server.port))
    assert secure_socket.version() == protocol_name
    secure_socket.write(b'hello wolfssl')
    secure_socket.read(1024)


def test_client_cert_verification_failure():
    """
    Test that a connection fails when the server requires client certificates
    but the server's CA (globalsign) does not verify the client's certificate.
    """
    import socket
    import time

    # Create a server with CERT_REQUIRED and globalsign CA
    # This server will require client certificates but won't accept
    # certificates signed by a different CA
    port = 11111
    with wolfSSLTestServer(
        ('localhost', port),
        version=wolfssl.PROTOCOL_TLS,
        verify=wolfssl.CERT_REQUIRED
    ) as server:
        server_thread = Thread(target=server.handle_request)
        server_thread.daemon = True
        server_thread.start()

        # Give the server a moment to start
        time.sleep(0.1)

        # Create a client socket
        client_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create a client context
        client_ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_TLS)

        # Wrap the socket with the client context
        # Set do_handshake_on_connect=False so we can explicitly call do_handshake()
        # and catch the error
        client_socket = client_ctx.wrap_socket(
            client_tcp_socket,
            do_handshake_on_connect=False
        )

        # Connect the TCP socket first
        client_socket.connect(('127.0.0.1', port))

        # Attempt handshake - this should fail because the client does not
        # send a cert/key.
        with pytest.raises(wolfssl.SSLError) as exc_info:
            client_socket.do_handshake()
            # Handshake appeared to succeed, try to read/write to trigger the error
            # The server should reject the connection due to certificate verification failure
            client_socket.write(b'hello')
            client_socket.read(1024)

        # Clean up (errors during close are expected if connection failed)
        try:
            client_socket.close()
        except Exception:
            pass
        try:
            client_tcp_socket.close()
        except Exception:
            pass

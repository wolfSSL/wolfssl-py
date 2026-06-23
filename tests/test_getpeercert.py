# -*- coding: utf-8 -*-
#
# test_getpeercert.py
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

import socket
from contextlib import contextmanager
from threading import Thread

import wolfssl


@contextmanager
def _client_server_session():
    """
    Establish a real TLS connection to a local server that does NOT request a
    client certificate. Yields (client_socket, server_result); server_result
    is populated (after the block exits) with the server's view of the peer:
    {"x509", "cert"} on success or {"error"} if a call raised.
    """
    result = {}

    server_ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_TLS, server_side=True)
    server_ctx.verify_mode = wolfssl.CERT_NONE
    server_ctx.load_cert_chain("certs/server-cert.pem", "certs/server-key.pem")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("localhost", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        ssock = server_ctx.wrap_socket(conn, server_side=True)
        try:
            ssock.read(1024)
            # Client sent no certificate: these must not raise.
            result["x509"] = ssock.get_peer_x509()
            result["cert"] = ssock.getpeercert()
            ssock.write(b"ok")
        except Exception as exc:  # pylint: disable=broad-except
            result["error"] = exc
        finally:
            ssock.close()

    server_thread = Thread(target=serve, daemon=True)
    server_thread.start()

    client_ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_TLS)
    client_ctx.verify_mode = wolfssl.CERT_NONE
    client = client_ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    client.connect(("localhost", port))
    client.write(b"hi")
    try:
        yield client, result
    finally:
        try:
            client.read(1024)
        except Exception:  # pylint: disable=broad-except
            pass
        client.close()
        server_thread.join(timeout=10)
        listener.close()


def test_getpeercert_returns_none_without_peer_cert():
    """
    F-5623: on a valid TLS connection where the peer presented no
    certificate (here, a server that does not request a client cert),
    getpeercert()/get_peer_x509() must return None instead of raising.
    """
    with _client_server_session() as (client, result):
        # The peer (server) always presents a certificate.
        server_cert = client.getpeercert()

    assert "error" not in result, "getpeercert raised: %r" % result.get("error")
    assert result["x509"] is None
    assert result["cert"] is None
    # Positive path: the server's certificate is still returned to the client.
    assert server_cert is not None


def test_wolfsslx509_accepts_session_for_backward_compat():
    """
    WolfSSLX509 historically accepted a WOLFSSL* session and fetched the peer
    certificate itself. That constructor form must keep working alongside the
    new WOLFSSL_X509* form used by get_peer_x509().
    """
    with _client_server_session() as (client, _result):
        from_session = wolfssl.WolfSSLX509(client.native_object)
        from_helper = client.get_peer_x509()

        # Both forms resolve to the same server certificate.
        assert from_session.get_subject_cn() != ""
        assert from_session.get_subject_cn() == from_helper.get_subject_cn()

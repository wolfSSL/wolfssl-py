#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#
# client.py
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

import sys
import socket
import argparse

try:
    import wolfssl
except ImportError:
    print("You must run 'python setup.py install' to use the examples")
    sys.exit()

def build_arg_parser():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument(
        "-?", "--help", action="help",
        help="show this help message and exit"
    )

    parser.add_argument(
        "-h", metavar="host", default="127.0.0.1",
        help="Host to connect to, default 127.0.0.1"
    )

    parser.add_argument(
        "-p", metavar="port", type=int, default=11111,
        help="Port to connect on, not 0, default 11111"
    )

    parser.add_argument(
        "-v", metavar="version", type=int, choices=[0, 1, 2, 3, 4, 5],
        default=5,
        help="SSL version [0-5]"
             "(SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3, SSLv23)"
    )

    parser.add_argument(
        "-u", action="store_true",
        help="Use UDP DTLS, add -v 0 for DTLSv1, -v 1 for DTLSv1.2 (default)"
    )

    parser.add_argument(
        "-l", metavar="ciphers", type=str, default="",
        help="Cipher suite list (: delimited)"
    )

    parser.add_argument(
        "-c", metavar="certificate", default="./certs/client-cert.pem",
        help="Certificate file,           default ./certs/client-cert.pem"
    )

    parser.add_argument(
        "-k", metavar="key", default="./certs/client-key.pem",
        help="Key file,                   default ./certs/client-key.pem"
    )

    parser.add_argument(
        "-A", metavar="ca_file", default="./certs/ca-cert.pem",
        help="Certificate Authority file, default ./certs/ca-cert.pem"
    )

    parser.add_argument(
        "-d", action="store_true",
        help="Disable client cert check"
    )

    parser.add_argument(
        "-n", action="store_true",
        help="Disable server hostname check "
             "(IP literal hosts are never hostname-checked)"
    )

    parser.add_argument(
        "-g", action="store_true",
        help="Send server HTTP GET"
    )

    parser.add_argument(
        "-C", action="store_true",
        help="Disable CRL"
    )

    parser.add_argument(
        "-r", metavar="crl_file", default="./certs/crl.pem",
        help="CRL file,                   default ./certs/crl.pem"
    )


    return parser


def get_SSLmethod(index):
    return (
        wolfssl.PROTOCOL_SSLv3,
        wolfssl.PROTOCOL_TLSv1,
        wolfssl.PROTOCOL_TLSv1_1,
        wolfssl.PROTOCOL_TLSv1_2,
        wolfssl.PROTOCOL_TLSv1_3,
        wolfssl.PROTOCOL_SSLv23
    )[index]

def get_DTLSmethod(index):
    return (
        wolfssl.PROTOCOL_DTLSv1,
        wolfssl.PROTOCOL_DTLSv1_2,
        wolfssl.PROTOCOL_DTLSv1_3
    )[index]

def is_ip_literal(host):
    # AI_NUMERICHOST never resolves, it only parses. Unlike
    # socket.inet_pton() it is available on every supported platform.
    try:
        socket.getaddrinfo(host, None, 0, 0, 0, socket.AI_NUMERICHOST)
        return True
    except socket.error:
        return False


def configure_verification(context, args):
    """
    Configure peer certificate and hostname verification on the context
    according to the parsed arguments. Returns the server_hostname to pass
    to wrap_socket() (None when no hostname check should be performed).

    When certificate verification is enabled (the default), hostname
    verification is enabled too so that a CA-trusted certificate issued for
    a different host is rejected. Pass -n to opt out explicitly (e.g. when
    using test certificates).

    IP literal hosts are not hostname-checked: wolfSSL_check_domain_name()
    only matches DNS names (iPAddress SANs are skipped on this path), and
    RFC 6066 forbids IP literals in SNI. Certificate verification against
    the CA still applies. Connect by DNS name to also verify the hostname.
    """
    if args.d:
        context.verify_mode = wolfssl.CERT_NONE
        context.check_hostname = False
        return None

    context.verify_mode = wolfssl.CERT_REQUIRED
    context.load_verify_locations(args.A)

    if args.n:
        context.check_hostname = False
        return None

    if is_ip_literal(args.h):
        print("Note: skipping hostname check for IP literal '{}'. "
              "Connect by DNS name to enable it.".format(args.h))
        context.check_hostname = False
        return None

    context.check_hostname = True
    return args.h


def main():
    args = build_arg_parser().parse_args()

    # DTLS connection  over UDP
    if args.u:
        if args.v > 2:
            args.v = 1
        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        context = wolfssl.SSLContext(get_DTLSmethod(args.v))
    # SSL/TLS connection over TCP
    else:
        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        context = wolfssl.SSLContext(get_SSLmethod(args.v))

    # enable debug, if native wolfSSL has been compiled with '--enable-debug'
    try:
        wolfssl.WolfSSL.enable_debug()
    except RuntimeError:
        pass

    context.load_cert_chain(args.c, args.k)

    server_hostname = configure_verification(context, args)

    if args.l:
        context.set_ciphers(args.l)

    secure_socket = None
    try:
        secure_socket = context.wrap_socket(
            bind_socket, server_hostname=server_hostname)
        
        if not args.C:
            secure_socket.enable_crl(1)
            secure_socket.load_crl_file(args.r, 1);
        
        secure_socket.connect((args.h, args.p))

        if args.g:
            secure_socket.write(b"GET / HTTP/1.1\n\n")
        else:
            secure_socket.write(b"hello wolfssl")

        print("\n", secure_socket.read(), "\n")

    except KeyboardInterrupt:
        print()

    finally:
        if secure_socket:
            secure_socket.close()


if __name__ == '__main__':
    main()

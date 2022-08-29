# -*- coding: utf-8 -*-
#
# __init__.py
#
# Copyright (C) 2006-2022 wolfSSL Inc.
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

# pylint: disable=too-many-instance-attributes, too-many-arguments
# pylint: disable=too-many-arguments, too-many-branches, too-many-locals
# pylint: disable=too-many-public-methods, too-many-statements

import sys
from functools import wraps
import errno
from socket import (
    socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_TYPE, error as socket_error
)

# pylint: disable=wildcard-import
from wolfssl.__about__ import *  # noqa: F401, F403
# pylint: enable=wildcard-import

try:
    from wolfssl._ffi import ffi as _ffi
    from wolfssl._ffi import lib as _lib
except ImportError:
    pass

from wolfssl.utils import t2b

from wolfssl.exceptions import (  # noqa: F401
    CertificateError, SSLError, SSLEOFError, SSLSyscallError,
    SSLWantReadError, SSLWantWriteError, SSLZeroReturnError
)

from wolfssl._methods import (  # noqa: F401
    PROTOCOL_SSLv23, PROTOCOL_SSLv3, PROTOCOL_TLSv1,
    PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2, PROTOCOL_TLSv1_3,
    PROTOCOL_TLS, PROTOCOL_DTLSv1, PROTOCOL_DTLSv1_2,
    PROTOCOL_DTLSv1_3, WolfSSLMethod as _WolfSSLMethod
)

CERT_NONE = 0
CERT_REQUIRED = 1

_VERIFY_MODE_LIST = [CERT_NONE, CERT_REQUIRED]

_SSL_SUCCESS = 1
_SSL_FILETYPE_PEM = 1
_SSL_ERROR_WANT_READ = 2
_SSL_ERROR_WANT_WRITE = 3

_SOCKADDR_SZ = 16

_PY3 = sys.version_info[0] == 3


class WolfSSL(object):

    @classmethod
    def enable_debug(self):
        _lib.wolfSSL_Debugging_ON()

    @classmethod
    def disable_debug(self):
        _lib.wolfSSL_Debugging_OFF()


class WolfSSLX509(object):
    """
    A WolfSSLX509 represents a X.509 certificate extracted from an SSL/TLS
    session. This class wraps the native wolfSSL WOLFSSL_X509 structure.
    """

    def __init__(self, session):
        self.native_object = _lib.wolfSSL_get_peer_certificate(session)

        if self.native_object == _ffi.NULL:
            raise SSLError("Unable to get internal WOLFSSL_X509 from wolfSSL")

    def get_subject_cn(self):
        cnPtr = _lib.wolfSSL_X509_get_subjectCN(self.native_object)
        if cnPtr == _ffi.NULL:
            return ''

        cn = _ffi.string(cnPtr).decode("ascii")

        return cn

    def get_next_altname(self):
        sanPtr = _lib.wolfSSL_X509_get_next_altname(self.native_object)
        if (sanPtr == _ffi.NULL):
            return None

        san = _ffi.string(sanPtr).decode("ascii")

        return san

    def get_altnames(self):

        altNames = []

        while True:
            name = self.get_next_altname()
            if name is None:
                break
            altNames.append(('DNS', name))

        return altNames

    def get_der(self):
        outSz = _ffi.new("int *")
        derPtr = _lib.wolfSSL_X509_get_der(self.native_object, outSz)

        if derPtr == _ffi.NULL:
            return None

        derBytes = _ffi.buffer(derPtr, outSz[0])

        return derBytes

class SSLContext(object):
    """
    An SSLContext holds various SSL-related configuration options and
    data, such as certificates and possibly a private key.
    """

    def __init__(self, protocol, server_side=None):
        _lib.wolfSSL_Init()
        method = _WolfSSLMethod(protocol, server_side)

        self.protocol = protocol
        self._server_side = server_side
        self._verify_mode = None
        self._check_hostname = False
        self._passwd_cb = None
        self._passwd_userdata = None
        self.native_object = _lib.wolfSSL_CTX_new(method.native_object)

        # wolfSSL_CTX_new() takes ownership of the method.
        # the method is freed later inside wolfSSL_CTX_free()
        # or if wolfSSL_CTX_new() failed to allocate the context object.
        method.native_object = _ffi.NULL

        if self.native_object == _ffi.NULL:
            raise MemoryError("Unable to allocate context object")

        # verify_mode initialization needs a valid native_object.
        self.verify_mode = CERT_NONE

    def __del__(self):
        if getattr(self, 'native_object', _ffi.NULL) != _ffi.NULL:
            _lib.wolfSSL_CTX_free(self.native_object)

    @property
    def verify_mode(self):
        """
        Whether to try to verify other peers’ certificates and how to behave
        if verification fails. This attribute must be one of CERT_NONE,
        CERT_OPTIONAL or CERT_REQUIRED.
        """
        return self._verify_mode

    @verify_mode.setter
    def verify_mode(self, value):
        if value not in _VERIFY_MODE_LIST:
            raise ValueError("verify_mode must be one of CERT_NONE, "
                             "CERT_OPTIONAL or CERT_REQUIRED")

        if value != self._verify_mode:
            self._verify_mode = value
            _lib.wolfSSL_CTX_set_verify(self.native_object,
                                        self._verify_mode,
                                        _ffi.NULL)

    @property
    def check_hostname(self):
        """
        Whether to match the peer certificate's hostname with match_hostname()
        in SSLSocket.do_handshake(). Context's verify mode must be set to
        CERT_REQUIRED, and the server hostname must be passed to wrap_socket()
        in order to match the hostname.
        """
        return self._check_hostname

    @check_hostname.setter
    def check_hostname(self, value):
        if value is not True and value is not False:
            raise ValueError("check_hostname must be either True or False")

        self._check_hostname = value

    def get_options(self):
        """
        Wrap native wolfSSL_CTX_get_options() function.
        """
        return _lib.wolfSSL_CTX_get_options(self.native_object)

    def set_options(self, value):
        """
        Wrap native wolfSSL_CTX_set_options() function.
        """
        return _lib.wolfSSL_CTX_set_options(self.native_object, value)

    def wrap_socket(self, sock, server_side=None,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None):
        """
        Wrap an existing Python socket sock and return an SSLSocket object.
        sock must be a SOCK_STREAM socket; other socket types are unsupported.

        The returned SSL socket is tied to the context, its settings and
        certificates. The parameters server_side, do_handshake_on_connect and
        suppress_ragged_eofs have the same meaning as in the top-level
        wrap_socket() function.
        """

        # if side was set at CTX init and here, they must match
        if self._server_side is not None and server_side is not None:
            if server_side != self._server_side:
                raise ValueError("SSLContext server_side value not consistent "
                                 "between init and wrap_socket()")

        if self._server_side is None:
            self._server_side = server_side

        if server_side is None and self._server_side is not None:
            server_side = self._server_side

        return SSLSocket(sock=sock, server_side=server_side,
                         do_handshake_on_connect=do_handshake_on_connect,
                         suppress_ragged_eofs=suppress_ragged_eofs,
                         _context=self, server_hostname=server_hostname)

    def set_ciphers(self, ciphers):
        """
        Set the available ciphers for sockets created with this context. It
        should be a string in the wolfSSL cipher list format. If no cipher can
        be selected (because compile-time options or other configuration
        forbids use of all the specified ciphers), an SSLError will be raised.
        """
        cipherBytes = t2b(ciphers)
        ret = _lib.wolfSSL_CTX_set_cipher_list(self.native_object,
                                               _ffi.new("char[]", cipherBytes))

        if ret != _SSL_SUCCESS:
            raise SSLError("Unable to set cipher list")

    def use_sni(self, server_hostname):
        """
        Sets the SNI hostname, wraps native wolfSSL_CTX_UseSNI()
        """

        sni = t2b(server_hostname)

        ret = _lib.wolfSSL_CTX_UseSNI(self.native_object, 0,
                                      sni, len(sni))

        if ret != _SSL_SUCCESS:
            raise SSLError("Unable to set wolfSSL CTX SNI")

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        """
        Load a private key and the corresponding certificate. The certfile
        string must be the path to a single file in PEM format containing
        the certificate as well as any number of CA certificates needed to
        establish the certificate's authenticity.

        The keyfile string, if present, must point to a file containing the
        private key in.

        If you are using a key protected cert or key file, you must call
        set_passwd_cb before calling load_cert_chain because wolfSSL
        validates the provided file the first time it is loaded.


        wolfSSL does not support loading a certificate file that contains
        both the certificate AND private key. In this case, users should
        split them into two separate files and load using the certfile
        and keyfile parameters, respectively.
        """
        if certfile is not None:
            ret = _lib.wolfSSL_CTX_use_certificate_chain_file(
                self.native_object, t2b(certfile))
            if ret != _SSL_SUCCESS:
                raise SSLError(
                    "Unable to load certificate chain. E(%d)" % ret)
        else:
            raise TypeError("certfile should be a valid filesystem path")

        if keyfile is not None:
            ret = _lib.wolfSSL_CTX_use_PrivateKey_file(
                self.native_object, t2b(keyfile), _SSL_FILETYPE_PEM)
            if ret != _SSL_SUCCESS:
                raise SSLError("Unable to load private key. E(%d)" % ret)

    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        """
        Load a set of "certification authority" (CA) certificates used to
        validate other peers' certificates when verify_mode is other than
        CERT_NONE. At least one of cafile or capath must be specified.

        The cafile string, if present, is the path to a file of concatenated
        CA certificates in PEM format.

        The capath string, if present, is the path to a directory containing
        several CA certificates in PEM format.
        """

        if cafile is None and capath is None and cadata is None:
            raise TypeError("cafile, capath and cadata cannot be all omitted")

        if cafile is not None or capath is not None:
            ret = _lib.wolfSSL_CTX_load_verify_locations(
                self.native_object,
                t2b(cafile) if cafile else _ffi.NULL,
                t2b(capath) if capath else _ffi.NULL)

            if ret != _SSL_SUCCESS:
                raise SSLError("Unable to load verify locations. E(%d)" % ret)

        if cadata is not None:
            ret = _lib.wolfSSL_CTX_load_verify_buffer(
                self.native_object, t2b(cadata),
                len(cadata), _SSL_FILETYPE_PEM)

            if ret != _SSL_SUCCESS:
                raise SSLError("Unable to load verify locations. E(%d)" % ret)

    def set_passwd_cb(self, callback, userdata=None):
        """
        This function can be called before loading a private key with a password.
        For example,
            password = "funPassphrase"
            self._ctx.set_passwd_cb(lambda *_: password)
            ...
            self._ctx.load_cert_chain()
        """
        if not callable(callback):
            raise TypeError("The specified callback must be callable")

        _passwd_helper = self._wrap_cb(callback)
        self._passwd_cb = _passwd_helper.callback
        _lib.wolfSSL_CTX_set_default_passwd_cb(self.native_object,
                                               self._passwd_cb)
        self._passwd_userdata = userdata # keep it alive

    def _wrap_cb(self, callback):
        @wraps(callback)
        def wrapper(sz, rw, userdata):
            return callback(sz, rw, self._passwd_userdata)
        return WolfsslPwd_cb(wrapper)

class SSLSocket(object):
    """
    This class implements a subtype of socket.socket that wraps the
    underlying OS socket in an SSL/TLS connection, providing secure
    read and write methods over that channel.
    """

    def __init__(self, sock=None, keyfile=None, certfile=None,
                 server_side=False, cert_reqs=CERT_NONE,
                 ssl_version=PROTOCOL_TLS, ca_certs=None,
                 do_handshake_on_connect=True, family=AF_INET,
                 sock_type=SOCK_STREAM, proto=0, fileno=None,
                 suppress_ragged_eofs=True, ciphers=None,
                 _context=None, server_hostname=None):

        # set options
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self._server_side = server_side

        # save socket
        self._sock = sock

        # set context
        if _context:
            self._context = _context
        else:
            if server_side and not certfile:
                raise ValueError("certfile must be specified for server-side "
                                 "operations")

            if keyfile and not certfile:
                raise ValueError("certfile must be specified")

            if certfile and not keyfile:
                keyfile = certfile

            self._context = SSLContext(ssl_version, server_side)
            self._context.verify_mode = cert_reqs
            if ca_certs:
                self._context.load_verify_locations(ca_certs)
            if certfile:
                self._context.load_cert_chain(certfile, keyfile)
            if ciphers:
                self._context.set_ciphers(ciphers)

            self.keyfile = keyfile
            self.certfile = certfile
            self.cert_reqs = cert_reqs
            self.ssl_version = ssl_version
            self.ca_certs = ca_certs
            self.ciphers = ciphers
            self.server_hostname = server_hostname

        # set SNI if passed in
        if server_hostname is not None:
            self._context.use_sni(server_hostname)

        # see if we are connected
        try:
            self._sock.getpeername()
        except socket_error as exception:
            if exception.errno != errno.ENOTCONN:
                raise
            connected = False
        else:
            connected = True

        self._closed = False
        self._connected = connected

        # create the SSL object
        self.native_object = _lib.wolfSSL_new(self.context.native_object)
        if self.native_object == _ffi.NULL:
            raise MemoryError("Unable to allocate ssl object")

        ret = _lib.wolfSSL_set_fd(self.native_object, self._sock.fileno())
        if ret != _SSL_SUCCESS:
            self._release_native_object()
            raise ValueError("Unable to set fd to ssl object")

        # match domain name / host name if set in context
        if server_hostname is not None:
            if self._context.check_hostname:

                sni = _ffi.new("char[]", server_hostname.encode("utf-8"))
                _lib.wolfSSL_check_domain_name(self.native_object,
                                               sni)

        if connected:
            try:
                if do_handshake_on_connect:
                    self.do_handshake()
            except SSLError:
                self._release_native_object()
                self._sock.close()
                raise

    def __del__(self):
        self._release_native_object()

    def _release_native_object(self):
        if getattr(self, 'native_object', _ffi.NULL) != _ffi.NULL:
            _lib.wolfSSL_free(self.native_object)
            self.native_object = _ffi.NULL

    def pending(self):
        return _lib.wolfSSL_pending(self.native_object)

    @property
    def context(self):
        """
        Returns the context used by this object.
        """
        return self._context

    def server_side(self):
        """
        Returns True for server-side socket, otherwise False.
        """
        return self._server_side;

    def dup(self):
        raise NotImplementedError("Can't dup() %s instances" %
                                  self.__class__.__name__)

    def _check_closed(self, call=None):
        if self.native_object == _ffi.NULL:
            raise ValueError("%s on closed or unwrapped secure channel" % call)

    def _check_connected(self):
        if not self._connected:
            # getpeername() will raise ENOTCONN if the socket is really
            # not connected; note that we can be connected even without
            # _connected being set, e.g. if connect() first returned
            # EAGAIN.
            self._sock.getpeername()

    def use_sni(self, server_hostname):
        """
        Sets the SNI hostname, wraps native wolfSSL_UseSNI()
        """

        sni = t2b(server_hostname)

        ret = _lib.wolfSSL_UseSNI(self.native_object, 0,
                                  sni, len(sni))

        if ret != _SSL_SUCCESS:
            raise SSLError("Unable to set wolfSSL SNI")

    def enable_crl(self, options):
        """
        Enables CRL certificate revocation
        """
        ret = _lib.wolfSSL_EnableCRL(self.native_object, options)

        if ret != _SSL_SUCCESS:
            raise SSLError("Unable to enable CRL ")

    def load_crl_file(self, path, filetype):
        """
        Load CRL certificate revocation
        """
        ret = _lib.wolfSSL_LoadCRLFile(self.native_object,
                                       t2b(path) if path else _ffi.NULL,
                                       filetype)

        if ret != _SSL_SUCCESS:
            raise SSLError("Unable to load CRL")

    def write(self, data):
        """
        Write DATA to the underlying secure channel.
        Returns number of bytes of DATA actually transmitted.
        """
        self._check_closed("write")
	# Check connected if not DTLS
        if self._context.protocol < PROTOCOL_DTLSv1:
            self._check_connected()
        # Complete handshake if DTLS connection
        else:
            self.do_handshake()

        data = t2b(data)

        return _lib.wolfSSL_write(self.native_object, data, len(data))

    def send(self, data, flags=0):
        if flags != 0:
            raise NotImplementedError("non-zero flags not allowed in calls to "
                                      "send() on %s" % self.__class__)

        return self.write(data)

    def sendall(self, data, flags=0):
        if flags != 0:
            raise NotImplementedError("non-zero flags not allowed in calls to "
                                      "sendall() on %s" % self.__class__)

        length = len(data)
        sent = 0

        while sent < length:
            ret = self.write(data[sent:])
            if (ret <= 0):
                #expect to receive 0 when peer is reset or closed
                err = _lib.wolfSSL_get_error(self.native_object, 0)
                if err == _SSL_ERROR_WANT_WRITE:
                    raise SSLWantWriteError()
                else:
                    raise SSLError("wolfSSL_write error (%d)" % err)

            sent += ret

        return None

    def sendto(self, data, flags_or_addr, addr=None):
        # Ensures not to send unencrypted data trying to use this method
        raise NotImplementedError("sendto not allowed on instances "
                                  "of %s" % self.__class__)

    def sendmsg(self, *args, **kwargs):
        # Ensures not to send unencrypted data trying to use this method
        raise NotImplementedError("sendmsg not allowed on instances "
                                  "of %s" % self.__class__)

    def sendfile(self, file, offset=0, count=None):
        # Ensures not to send unencrypted files trying to use this method
        raise NotImplementedError("sendfile not allowed on instances "
                                  "of %s" % self.__class__)

    def read(self, length=1024, buffer=None):
        """
        Read up to LENGTH bytes and return them.
        Return zero-length string on EOF.
        """
        self._check_closed("read")
        # Check connected if not DTLS
        if self._context.protocol < PROTOCOL_DTLSv1:
            self._check_connected()
        # Complete handshake if DTLS connection
        else:
            self.do_handshake()

        if buffer is not None:
            raise ValueError("buffer not allowed in calls to "
                             "read() on %s" % self.__class__)

        data = _ffi.new('byte[%d]' % length)
        length = _lib.wolfSSL_read(self.native_object, data, length)

        if length < 0:
            err = _lib.wolfSSL_get_error(self.native_object, 0)
            if err == _SSL_ERROR_WANT_READ:
                raise SSLWantReadError()
            else:
                raise SSLError("wolfSSL_read error (%d)" % err)

        return _ffi.buffer(data, length)[:] if length > 0 else b''

    def recv(self, length=1024, flags=0):
        if flags != 0:
            raise NotImplementedError("non-zero flags not allowed in calls to "
                                      "recv() on %s" % self.__class__)

        return self.read(length=length)

    def recv_into(self, buffer, nbytes=None, flags=0):
        """
        Read nbytes bytes and place into buffer. If nbytes is 0, read up
        to full size of buffer.
        """
        self._check_closed("read")
        if self._context.protocol < PROTOCOL_DTLSv1:
            self._check_connected()

        if buffer is None:
            raise ValueError("buffer cannot be None")

        if nbytes is None:
            nbytes = len(buffer)
        else:
            nbytes = min(len(buffer), nbytes)

        if nbytes == 0:
            return 0

        data = _ffi.from_buffer(buffer)
        length = _lib.wolfSSL_read(self.native_object, data, nbytes)

        if length < 0:
            err = _lib.wolfSSL_get_error(self.native_object, 0)
            if err == _SSL_ERROR_WANT_READ:
                raise SSLWantReadError()
            else:
                raise SSLError("wolfSSL_read error (%d)" % err)

        return length


    def recvfrom(self, length=1024, flags=0):
        # Ensures not to receive encrypted data trying to use this method
        raise NotImplementedError("recvfrom not allowed on instances "
                                  "of %s" % self.__class__)

    def recvfrom_into(self, buffer, nbytes=None, flags=0):
        # Ensures not to receive encrypted data trying to use this method
        raise NotImplementedError("recvfrom_into not allowed on instances "
                                  "of %s" % self.__class__)

    def recvmsg(self, *args, **kwargs):
        raise NotImplementedError("recvmsg not allowed on instances of %s" %
                                  self.__class__)

    def recvmsg_into(self, *args, **kwargs):
        raise NotImplementedError("recvmsg_into not allowed on instances of "
                                  "%s" % self.__class__)

    def shutdown(self, how):
        if self.native_object != _ffi.NULL:
            _lib.wolfSSL_shutdown(self.native_object)
            self._release_native_object()
        if self._context.protocol < PROTOCOL_DTLSv1:
            self._sock.shutdown(how)

    def unwrap(self):
        """
        Unwraps the underlying OS socket from the SSL/TLS connection.
        Returns the wrapped OS socket.
        """
        if self.native_object != _ffi.NULL:
            _lib.wolfSSL_set_fd(self.native_object, -1)

        sock = socket(family=self._sock.family,
                      sock_type=self._sock.type,
                      proto=self._sock.proto,
                      fileno=self._sock.fileno())

        sock.settimeout(self._sock.gettimeout())
        self._sock.detach()

        return sock

    def add_peer(self, addr):
            peerAddr = _lib.wolfSSL_dtls_create_peer(addr[1],t2b(addr[0]))  
            if peerAddr == _ffi.NULL:
                raise SSLError("Failed to create peer")
            ret = _lib.wolfSSL_dtls_set_peer(self.native_object, peerAddr,
                                             _SOCKADDR_SZ)
            if ret != _SSL_SUCCESS:
                raise SSLError("Unable to set dtls peer. E(%d)" % ret)
            _lib.wolfSSL_dtls_free_peer(peerAddr)  

    def do_handshake(self, block=False):  # pylint: disable=unused-argument
        """
        Perform a TLS/SSL handshake.
        """
        self._check_closed("do_handshake")
        if self._context.protocol < PROTOCOL_DTLSv1:
            self._check_connected()

        if self._server_side:
            ret = _lib.wolfSSL_accept(self.native_object)
        else:
            ret = _lib.wolfSSL_connect(self.native_object)

        if ret != _SSL_SUCCESS:
            err = _lib.wolfSSL_get_error(self.native_object, 0)
            if err == _SSL_ERROR_WANT_READ:
                raise SSLWantReadError()
            elif err == _SSL_ERROR_WANT_WRITE:
                raise SSLWantWriteError()
            else:
                eBuf = _ffi.new("char[80]")
                eStr = _ffi.string(_lib.wolfSSL_ERR_error_string(err,
                                   eBuf)).decode("ascii")

                if 'ASN no signer error to confirm' in eStr or err == -188:
                    # Some Python ssl consumers explicitly check error message
                    # for 'certificate verify failed'
                    raise SSLError("do_handshake failed with error %d, "
                                   "certificate verify failed" % err)

                # get alert code and string to put in exception msg
                alertHistoryPtr = _ffi.new("WOLFSSL_ALERT_HISTORY*")
                alertRet = _lib.wolfSSL_get_alert_history(self.native_object,
                                                          alertHistoryPtr)
                if alertRet == _SSL_SUCCESS:
                    alertHistory = alertHistoryPtr[0]
                    code = alertHistory.last_rx.code
                    alertDesc = _lib.wolfSSL_alert_type_string_long(code)
                    if alertDesc != _ffi.NULL:
                        alertStr = _ffi.string(alertDesc).decode("ascii")
                    else:
                        alertStr = ''

                    raise SSLError("do_handshake failed with error %d: %s. "
                                   "alert (%d): %s" %
                                   (err, eStr, code, alertStr))
                else:
                    raise SSLError("do_handshake failed with error %d: %s" %
                                   (err, eStr))

    def _real_connect(self, addr, connect_ex):
        if self._server_side:
            raise ValueError("can't connect in server-side mode")

        # Here we assume that the socket is client-side, and not
        # connected at the time of the call.  We connect it, then wrap it.
        if self._connected:
            raise ValueError("attempt to connect already-connected SSLSocket!")

        err = 0
        ret = _SSL_SUCCESS
 
        if self._context.protocol >= PROTOCOL_DTLSv1:
            self.add_peer(addr) 
        else:
            if connect_ex:
                err = self._sock.connect_ex(addr)
            else:
                err = 0
                self._sock.connect(addr)

        if err == 0 and ret == _SSL_SUCCESS:
            self._connected = True
            if self.do_handshake_on_connect:
                self.do_handshake()

        return err

    def connect(self, addr):
        """
        Connects to remote ADDR, and then wraps the connection in a secure
        channel.
        """
        self._real_connect(addr, False)

    def connect_ex(self, addr):
        """
        Connects to remote ADDR, and then wraps the connection in a secure
        channel.
        """
        return self._real_connect(addr, True)

    def accept(self):
        """
        Accepts a new connection from a remote client, and returns a tuple
        containing that new connection wrapped with a server-side secure
        channel, and the address of the remote client.
        """
        if not self._server_side:
            raise ValueError("can't accept in client-side mode")

        newsock, addr = self._sock.accept()
        newsock = self.context.wrap_socket(
            newsock,
            do_handshake_on_connect=self.do_handshake_on_connect,
            suppress_ragged_eofs=self.suppress_ragged_eofs,
            server_side=True)

        return newsock, addr

    def get_peer_x509(self):
        """
        Returns WolfSSLX509 object representing the peer's certificate,
        after making a successful SSL/TLS connection.
        """
        if self.native_object == _ffi.NULL:
            return _ffi.NULL

        return WolfSSLX509(self.native_object)

    def getpeercert(self, binary_form=False):
        """
        Compatibility wrapper to match Python ssl module's getpeercert()
        function.
        """

        x509 = self.get_peer_x509()

        if not x509:
            return x509

        if binary_form:
            return x509.get_der()

        return {'subject': ((('commonName', x509.get_subject_cn()),),),
                'subjectAltName': x509.get_altnames() }

    # The following functions expose functionality of the underlying
    # Socket object. These are also exposed through Python's ssl module
    # API and are provided here for compatibility.
    def close(self):
        self._sock.close()

    def fileno(self):
        """
        Return file descriptor of underlying socket.
        """
        return self._sock.fileno()

    def gettimeout(self):
        """
        Return the socket timeout of the underlying wrapped socket
        """
        return self._sock.gettimeout()

    def settimeout(self, timeout):
        """
        Set the timeout on the underlying wrapped socket
        """
        self._sock.settimeout(timeout)

    def getpeername(self):
        """
        Return the remote address that the underlying socket is connected to
        """
        return self._sock.getpeername()

    def getsockname(self):
        """
        Return the underlying socket's address
        """
        return self._sock.getsockname()



def wrap_socket(sock, keyfile=None, certfile=None, server_side=False,
                cert_reqs=CERT_NONE, ssl_version=PROTOCOL_TLS, ca_certs=None,
                do_handshake_on_connect=True, suppress_ragged_eofs=True,
                ciphers=None):
    """
    Takes an instance sock of socket.socket, and returns an instance of
    wolfssl.SSLSocket, wrapping the underlying socket in an SSL context.

    The sock parameter must be a SOCK_STREAM socket; other socket types are
    unsupported.

    The keyfile and certfile parameters specify optional files with proper
    key and the certificates used to identify the local side of the connection.

    The parameter server_side is a boolean which identifies whether server-side
    or client-side behavior is desired from this socket.

    The parameter cert_reqs specifies whether a certificate is required from
    the other side of the connection, and whether it will be validated if
    provided.
    It must be one of the three values:

        * CERT_NONE (certificates ignored)
        * CERT_OPTIONAL (not required, but validated if provided)
        * CERT_REQUIRED (required and validated)

    If the value of this parameter is not CERT_NONE, then the ca_certs
    parameter must point to a file of CA certificates.

    The ca_certs file contains a set of concatenated “certification authority”
    certificates, which are used to validate certificates passed from the other
    end of the connection.

    The parameter ssl_version specifies which version of the SSL protocol to
    use. Typically, the server chooses a particular protocol version, and the
    client must adapt to the server’s choice. Most of the versions are not
    interoperable with the other versions. If not specified, the default is
    PROTOCOL_TLS; it provides the most compatibility with other versions.

    Here’s a table showing which versions in a client (down the side) can
    connect to which versions in a server (along the top):

    +------------------+-------+-----+-------+---------+---------+
    | client \\ server  | SSLv3 | TLS | TLSv1 | TLSv1.1 | TLSv1.2 |
    +------------------+-------+-----+-------+---------+---------+
    | SSLv3            | yes   | yes | no    | no      | no      |
    +------------------+-------+-----+-------+---------+---------+
    | TLS (SSLv23)     | yes   | yes | yes   | yes     | yes     |
    +------------------+-------+-----+-------+---------+---------+
    | TLSv1            | no    | yes | yes   | no      | no      |
    +------------------+-------+-----+-------+---------+---------+
    | TLSv1.1          | no    | yes | no    | yes     | no      |
    +------------------+-------+-----+-------+---------+---------+
    | TLSv1.2          | no    | yes | no    | no      | yes     |
    +------------------+-------+-----+-------+---------+---------+

    Note:
        Which connections succeed will vary depending on the versions of the
        ssl providers on both sides of the communication.

    The ciphers parameter sets the available ciphers for this SSL object. It
    should be a string in the wolfSSL cipher list format.

    The parameter do_handshake_on_connect specifies whether to do the SSL
    handshake automatically after doing a socket.connect(), or whether the
    application program will call it explicitly, by invoking the
    SSLSocket.do_handshake() method. Calling SSLSocket.do_handshake()
    explicitly gives the program control over the blocking behavior of the
    socket I/O involved in the handshake.

    The parameter suppress_ragged_eofs is not supported yet.
    """
    return SSLSocket(sock=sock, keyfile=keyfile, certfile=certfile,
                     server_side=server_side, cert_reqs=cert_reqs,
                     ssl_version=ssl_version, ca_certs=ca_certs,
                     do_handshake_on_connect=do_handshake_on_connect,
                     suppress_ragged_eofs=suppress_ragged_eofs,
                     ciphers=ciphers)

class WolfsslPwd_cb(object):
    def __init__(self, password):
        self._passwd_wrapper = password

    @property
    def callback(self):
        if self._passwd_wrapper is None or isinstance(self._passwd_wrapper, bytes):
            return _ffi.NULL
        elif callable(self._passwd_wrapper):
            return _ffi.callback("pem_password_cb", self._get_passwd)
        else:
            raise TypeError("Not callable or missing arguments")

    def _get_passwd(self, passwd, sz, rw, userdata):
        try:
            result = self._passwd_wrapper(sz, rw, userdata)
            if not isinstance(result, bytes):
                raise ValueError("Problem, expected String, not bytes")
            if len(result) > sz:
                raise ValueError("Problem with password returned being long")
            for i in range(len(result)):
                passwd[i] = result[i:i + 1]
            return len(result)
        except Exception as e:
            raise ValueError("Problem getting password from callback")

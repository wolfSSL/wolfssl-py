# -*- coding: utf-8 -*-
#
# build_ffi.py
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

# pylint: disable=missing-docstring, invalid-name

import argparse
from contextlib import contextmanager
from distutils.util import get_platform
from cffi import FFI
from wolfssl._version import __wolfssl_version__ as version
import wolfssl._openssl as openssl
import subprocess
import shlex
import os
import sys
from ctypes import cdll
from collections import namedtuple

libwolfssl_path = ""


def local_path(path):
    """ Return path relative to the root of this project
    """
    current = os.path.abspath(os.getcwd())
    return os.path.abspath(os.path.join(current, path))


WOLFSSL_SRC_PATH = local_path("lib/wolfssl")


def wolfssl_inc_path():
    wolfssl_path = os.environ.get("USE_LOCAL_WOLFSSL")
    if wolfssl_path is None:
        return local_path("lib/wolfssl")
    else:
        if os.path.isdir(wolfssl_path) and os.path.exists(wolfssl_path):
            return wolfssl_path + "/include"
        else:
            return "/usr/local/include"


def wolfssl_lib_path():
    wolfssl_path = os.environ.get("USE_LOCAL_WOLFSSL")
    if wolfssl_path is None:
        return local_path("lib/wolfssl/{}/{}/lib".format(
                          get_platform(), version))
    else:
        if os.path.isdir(wolfssl_path) and os.path.exists(wolfssl_path):
            return wolfssl_path + "/lib"
        else:
            return "/usr/local/lib"


def call(cmd):
    print("Calling: '{}' from working directory {}".format(cmd, os.getcwd()))

    old_env = os.environ["PATH"]
    os.environ["PATH"] = "{}:{}".format(WOLFSSL_SRC_PATH, old_env)
    subprocess.check_call(cmd, shell=True, env=os.environ)
    os.environ["PATH"] = old_env


@contextmanager
def chdir(new_path, mkdir=False):
    old_path = os.getcwd()

    if mkdir:
        try:
            os.mkdir(new_path)
        except OSError:
            pass

    try:
        yield os.chdir(new_path)
    finally:
        os.chdir(old_path)


def checkout_ref(ref):
    """ Ensure that we have the right version
    """
    with chdir(WOLFSSL_SRC_PATH):
        current = ""
        try:
            current = subprocess.check_output(
                ["git", "describe", "--all", "--exact-match"]
            ).strip().decode().split('/')[-1]
        except:
            pass

        if current != ref:
            tags = subprocess.check_output(
                ["git", "tag"]
            ).strip().decode().split("\n")

            if ref != "master" and ref not in tags:
                call("git fetch --depth=1 origin tag {}".format(ref))

            call("git checkout --force {}".format(ref))

            return True  # rebuild needed

    return False


def ensure_wolfssl_src(ref):
    """ Ensure that wolfssl sources are presents and up-to-date
    """
    if not os.path.isdir("lib"):
        os.mkdir("lib")
        with chdir("lib"):
            subprocess.run(["git", "clone", "--depth=1", "https://github.com/wolfssl/wolfssl"])

    if not os.path.isdir(os.path.join(WOLFSSL_SRC_PATH, "wolfssl")):
        subprocess.run(["git", "submodule", "update", "--init", "--depth=1"])

    return checkout_ref(ref)


def make_flags(prefix, debug):
    """ Returns compilation flags
    """
    flags = []
    cflags = []

    if get_platform() in ["linux-x86_64", "linux-i686"]:
        cflags.append("-fpic")

    # install location
    flags.append("--prefix={}".format(prefix))

    # lib only
    flags.append("--disable-shared")
    flags.append("--disable-examples")

    # dtls 1.3
    flags.append("--enable-dtls13")

    # dtls
    flags.append("--enable-dtls")

    # crl
    flags.append("--enable-crl")

    # openssl extra
    flags.append("--enable-opensslextra")

    # for urllib3 - requires SNI (tlsx), options (openssl compat), peer cert
    flags.append("--enable-tlsx")
    flags.append("--enable-opensslextra")
    cflags.append("-DKEEP_PEER_CERT")

    # for pyOpenSSL
    flags.append("--enable-secure-renegotiation")
    flags.append("--enable-opensslall")
    cflags.append("-DFP_MAX_BITS=8192")
    cflags.append("-DHAVE_EX_DATA")
    cflags.append("-DOPENSSL_COMPATIBLE_DEFAULTS")

    if debug:
        flags.append("--enable-debug")

    # Note: websocket-client test server (echo.websocket.org) only supports
    # TLS 1.2 with TLS_RSA_WITH_AES_128_CBC_SHA
    # If compiling for use with websocket-client, must enable static RSA suites.
    # cflags.append("-DWOLFSSL_STATIC_RSA")

    joined_flags = " ".join(flags)
    joined_cflags = " ".join(cflags)

    return joined_flags + " CFLAGS=\"" + joined_cflags + "\""


def make(configure_flags):
    """ Create a release of wolfSSL C library
    """
    with chdir(WOLFSSL_SRC_PATH):
        call("git clean -fdX")

        try:
            call("./autogen.sh")
        except subprocess.CalledProcessError:
            call("libtoolize")
            call("./autogen.sh")

        call("./configure {}".format(configure_flags))
        call("make")
        call("make install")


def build_wolfssl(ref, debug=False):
    prefix = local_path("lib/wolfssl/{}/{}".format(
        get_platform(), ref))
    libfile = os.path.join(prefix, 'lib/libwolfssl.la')

    rebuild = ensure_wolfssl_src(ref)

    if rebuild or not os.path.isfile(libfile):
        make(make_flags(prefix, debug))


def make_optional_func_list(libwolfssl_path, funcs):
    sys.stderr.write("\nlibwolfssl Path: %s\n" % libwolfssl_path)
    if libwolfssl_path.endswith(".so"):
        libwolfssl = cdll.LoadLibrary(libwolfssl_path)
        defined = []
        for func in funcs:
            try:
                getattr(libwolfssl, func.name)
                defined.append(func)
            except AttributeError as _:
                pass
    # Can't discover functions in a static library with ctypes. Need to fall
    # back to running nm as a subprocess.
    else:
        nm_cmd = "nm --defined-only {}".format(libwolfssl_path)
        result = subprocess.run(shlex.split(nm_cmd), capture_output=True)
        nm_stdout = result.stdout.decode()
        defined = [func for func in funcs if func.name in nm_stdout]

    return defined


def get_libwolfssl():
    libwolfssl_path = os.path.join(wolfssl_lib_path(), "libwolfssl.a")
    if not os.path.exists(libwolfssl_path):
        libwolfssl_path = os.path.join(wolfssl_lib_path(), "libwolfssl.so")
        if not os.path.exists(libwolfssl_path):
            return 0
        else:
            return 1
    else:
        return 1


def generate_libwolfssl():
    ensure_wolfssl_src(version)
    prefix = local_path("lib/wolfssl/{}/{}".format(
        get_platform(), version))
    make(make_flags(prefix, False))

# detect features if user has built against local wolfSSL library
# if they are not, we are controlling build options above
local_wolfssl = os.environ.get("USE_LOCAL_WOLFSSL")
if local_wolfssl:
    # Try to do native wolfSSL/wolfCrypt feature detection.
    # Open <wolfssl/options.h> header to parse for #define's
    # This will throw a FileNotFoundError if not able to find options.h
    optionsHeaderPath = wolfssl_inc_path() + "/wolfssl/options.h"
    optionsHeader = open(optionsHeaderPath, 'r')
    optionsHeaderStr = optionsHeader.read()
    optionsHeader.close()
    # require HAVE_SNI (--enable-sni) in native lib
    if '#define HAVE_SNI' not in optionsHeaderStr:
        raise RuntimeError("wolfSSL needs to be compiled with --enable-sni")

    # require OPENSSL_EXTRA (--enable-opensslextra) in native lib
    if '#define OPENSSL_EXTRA' not in optionsHeaderStr:
        raise RuntimeError("wolfSSL needs to be compiled with "
            "--enable-opensslextra")
    featureDetection = 1
    sys.stderr.write("\nDEBUG: Found <wolfssl/options.h>, attempting native "
                     "feature detection\n")

else:
    optionsHeaderStr = ""
    featureDetection = 0
    sys.stderr.write("\nDEBUG: Skipping native feature detection, build not "
                     "using USE_LOCAL_WOLFSSL\n")
    if get_libwolfssl() == 0:
        generate_libwolfssl()
        get_libwolfssl()

# default values
OLDTLS_ENABLED = 1

if featureDetection:
    OLDTLS_ENABLED = 0 if '#define NO_OLD_TLS' in optionsHeaderStr else 1

sys.stderr.write("\nOLDTLS: %d\n" % OLDTLS_ENABLED)

WolfFunction = namedtuple("WolfFunction", ["name", "native_sig", "ossl_sig"])
# Depending on how wolfSSL was configured, the functions below may or may not be
# defined.
optional_funcs = [
    WolfFunction("wolfSSL_ERR_func_error_string",
                 "const char* wolfSSL_ERR_func_error_string(unsigned long)",
                 "const char* ERR_func_error_string(unsigned long)"),
    WolfFunction("wolfSSL_ERR_lib_error_string",
                 "const char* wolfSSL_ERR_lib_error_string(unsigned long)",
                 "const char* ERR_lib_error_string(unsigned long)"),
    WolfFunction("wolfSSL_X509_EXTENSION_dup",
                 "WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_dup(WOLFSSL_X509_EXTENSION*)",
                 "X509_EXTENSION* X509_EXTENSION_dup(X509_EXTENSION*)")
]
optional_funcs = make_optional_func_list(libwolfssl_path, optional_funcs)

source = """
    #include <wolfssl/options.h>
    #include <wolfssl/ssl.h>

    int OLDTLS_ENABLED = """ + str(OLDTLS_ENABLED) + """;
"""
ffi_source = source + openssl.source

ffi = FFI()

ffi.set_source(
    "wolfssl._ffi",
    ffi_source,
    include_dirs=[wolfssl_inc_path()],
    library_dirs=[wolfssl_lib_path()],
    libraries=["wolfssl"],
)

cdef = """
    /*
     * Constants
     */
    static const long SOCKET_PEER_CLOSED_E;

    /*
     * Types
     */
    typedef unsigned char byte;
    typedef unsigned int word32;

    extern int OLDTLS_ENABLED;

    /*
     * Opaque structs.
     */
    typedef ... WOLFSSL_CTX;
    typedef ... WOLFSSL;
    typedef ... WOLFSSL_X509;
    typedef ... WOLFSSL_X509_EXTENSION;
    typedef ... WOLFSSL_X509_STORE_CTX;
    typedef ... WOLFSSL_X509_NAME;
    typedef ... WOLFSSL_X509_NAME_ENTRY;
    typedef ... WOLFSSL_METHOD;
    typedef ... WOLFSSL_ASN1_TIME;
    typedef ... WOLFSSL_ASN1_GENERALIZEDTIME;
    typedef ... WOLFSSL_ASN1_STRING;
    typedef ... WOLFSSL_ASN1_OBJECT;

    /*
     * Non-opaque structs, where we need access to fields.
     */
    typedef struct WOLFSSL_ALERT {
        int code;
        int level;
    } WOLFSSL_ALERT;
    typedef struct WOLFSSL_ALERT_HISTORY {
        WOLFSSL_ALERT last_rx;
        WOLFSSL_ALERT last_tx;
    } WOLFSSL_ALERT_HISTORY;

    typedef int (*VerifyCallback)(int, WOLFSSL_X509_STORE_CTX*);
    typedef int pem_password_cb(char*, int, int, void*);
    typedef int (*CallbackSniRecv)(WOLFSSL*, int*, void*);

    /*
     * Memory
     */
    void  wolfSSL_Free(void*);
    void  wolfSSL_OPENSSL_free(void*);

    /*
     * Debugging
     */
    void wolfSSL_Debugging_ON();
    void wolfSSL_Debugging_OFF();

    /*
     * SSL/TLS Method functions
     */
"""

if OLDTLS_ENABLED:
    sys.stderr.write("\nAdding OLDTLS\n")
    cdef += """
    WOLFSSL_METHOD* wolfTLSv1_1_server_method(void);
    WOLFSSL_METHOD* wolfTLSv1_1_client_method(void);

    WOLFSSL_METHOD* wolfDTLSv1_server_method(void);
    WOLFSSL_METHOD* wolfDTLSv1_client_method(void);
    """

cdef += """
    WOLFSSL_METHOD* wolfTLSv1_2_server_method(void);
    WOLFSSL_METHOD* wolfTLSv1_2_client_method(void);

    WOLFSSL_METHOD* wolfTLSv1_3_server_method(void);
    WOLFSSL_METHOD* wolfTLSv1_3_client_method(void);

    WOLFSSL_METHOD* wolfSSLv23_server_method(void);
    WOLFSSL_METHOD* wolfSSLv23_client_method(void);

    WOLFSSL_METHOD* wolfSSLv23_method(void);

    WOLFSSL_METHOD* wolfDTLSv1_2_server_method(void);
    WOLFSSL_METHOD* wolfDTLSv1_2_client_method(void);

    WOLFSSL_METHOD* wolfDTLSv1_3_server_method(void);
    WOLFSSL_METHOD* wolfDTLSv1_3_client_method(void);
    """
if OLDTLS_ENABLED:
    cdef += """
    WOLFSSL_METHOD* wolfTLSv1_1_method(void);
    """
cdef += """
    WOLFSSL_METHOD* wolfTLSv1_2_method(void);

    /*
     * SSL/TLS Context functions
     */
    WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);
    void         wolfSSL_CTX_free(WOLFSSL_CTX*);

    void wolfSSL_CTX_set_verify(WOLFSSL_CTX*, int, VerifyCallback);
    int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX*, const char*);
    int  wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX*, const char*, int);
    int  wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX*, const char*,
            const char*);
    int  wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX*, const unsigned char*,
            long,int);
    int  wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX*, const char *);
    int  wolfSSL_CTX_UseSNI(WOLFSSL_CTX*, unsigned char, const void*,
            unsigned short);
    long wolfSSL_CTX_get_options(WOLFSSL_CTX*);
    long wolfSSL_CTX_set_options(WOLFSSL_CTX*, long);
    void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX*, pem_password_cb*);
    int  wolfSSL_CTX_set_tlsext_servername_callback(WOLFSSL_CTX*,
            CallbackSniRecv);
    long wolfSSL_CTX_set_mode(WOLFSSL_CTX*, long);

    /*
     * SSL/TLS Session functions
     */
    void wolfSSL_Init();
    WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);
    void  wolfSSL_free(WOLFSSL*);

    int           wolfSSL_set_fd(WOLFSSL*, int);
    int           wolfSSL_get_error(WOLFSSL*, int);
    char*         wolfSSL_ERR_error_string(int, char*);
    int           wolfSSL_negotiate(WOLFSSL*);
    int           wolfSSL_connect(WOLFSSL*);
    int           wolfSSL_accept(WOLFSSL*);
    int           wolfSSL_write(WOLFSSL*, const void*, int);
    int           wolfSSL_read(WOLFSSL*, void*, int);
    int           wolfSSL_pending(WOLFSSL*);
    int           wolfSSL_shutdown(WOLFSSL*);
    WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL*);
    int           wolfSSL_UseSNI(WOLFSSL*, unsigned char, const void*,
                      unsigned short);
    int           wolfSSL_check_domain_name(WOLFSSL*, const char*);
    int           wolfSSL_get_alert_history(WOLFSSL*, WOLFSSL_ALERT_HISTORY*);
    const char*   wolfSSL_get_servername(WOLFSSL*, unsigned char);
    int           wolfSSL_set_tlsext_host_name(WOLFSSL*, const char*);
    long          wolfSSL_ctrl(WOLFSSL*, int, long, void*);
    void          wolfSSL_set_connect_state(WOLFSSL*);
    int           wolfSSL_EnableCRL(WOLFSSL*, int);
    int           wolfSSL_LoadCRLFile(WOLFSSL*, const char*, int);
    void*         wolfSSL_dtls_create_peer(int, char*);
    int           wolfSSL_dtls_free_peer(void*);
    int           wolfSSL_dtls_set_peer(WOLFSSL*, void*, unsigned int);

    /*
     * WOLFSSL_X509 functions
     */
    char*                    wolfSSL_X509_get_subjectCN(void*);
    char*                    wolfSSL_X509_get_next_altname(void*);
    const unsigned char*     wolfSSL_X509_get_der(void*, int*);
    WOLFSSL_X509*            wolfSSL_X509_STORE_CTX_get_current_cert(
                                 WOLFSSL_X509_STORE_CTX*);
    int                      wolfSSL_X509_up_ref(WOLFSSL_X509*);
    void                     wolfSSL_X509_free(WOLFSSL_X509*);
    int                      wolfSSL_X509_STORE_CTX_get_error(
                                 WOLFSSL_X509_STORE_CTX*);
    int                      wolfSSL_X509_STORE_CTX_get_error_depth(
                                 WOLFSSL_X509_STORE_CTX*);
    int                      wolfSSL_get_ex_data_X509_STORE_CTX_idx(void);
    void*                    wolfSSL_X509_STORE_CTX_get_ex_data(
                                 WOLFSSL_X509_STORE_CTX*, int);
    void                     wolfSSL_X509_STORE_CTX_set_error(
                                 WOLFSSL_X509_STORE_CTX*, int);
    WOLFSSL_X509_NAME*       wolfSSL_X509_get_subject_name(WOLFSSL_X509*);
    char*                    wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME*,
                                 char*, int);
    WOLFSSL_ASN1_TIME*       wolfSSL_X509_get_notBefore(const WOLFSSL_X509*);
    WOLFSSL_ASN1_TIME*       wolfSSL_X509_get_notAfter(const WOLFSSL_X509*);
    int                      wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME*);
    WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_get_entry(WOLFSSL_X509_NAME*, int);
    WOLFSSL_ASN1_OBJECT*     wolfSSL_X509_NAME_ENTRY_get_object(
                                 WOLFSSL_X509_NAME_ENTRY*);
    WOLFSSL_ASN1_STRING*     wolfSSL_X509_NAME_ENTRY_get_data(WOLFSSL_X509_NAME_ENTRY*);
    int                      wolfSSL_X509_NAME_get_index_by_NID(WOLFSSL_X509_NAME*, int,
                                 int);
    int                      wolfSSL_X509_NAME_cmp(const WOLFSSL_X509_NAME*,
                                 const WOLFSSL_X509_NAME*);
    int                      wolfSSL_X509_get_ext_count(const WOLFSSL_X509*);
    WOLFSSL_X509_EXTENSION*  wolfSSL_X509_get_ext(const WOLFSSL_X509*, int);
    void                     wolfSSL_X509_EXTENSION_free(
                                 WOLFSSL_X509_EXTENSION*);
    WOLFSSL_ASN1_OBJECT*     wolfSSL_X509_EXTENSION_get_object(
                                 WOLFSSL_X509_EXTENSION*);
    WOLFSSL_ASN1_STRING*     wolfSSL_X509_EXTENSION_get_data(
                                 WOLFSSL_X509_EXTENSION*);
    WOLFSSL_X509*            wolfSSL_X509_dup(WOLFSSL_X509*);

    /*
     * ASN.1
     */
    int                wolfSSL_ASN1_STRING_length(WOLFSSL_ASN1_STRING*);
    int                wolfSSL_ASN1_STRING_type(const WOLFSSL_ASN1_STRING*);
    unsigned char*     wolfSSL_ASN1_STRING_data(WOLFSSL_ASN1_STRING*);
    WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_to_generalizedtime(WOLFSSL_ASN1_TIME*,
                           WOLFSSL_ASN1_TIME**);
    void               wolfSSL_ASN1_GENERALIZEDTIME_free(
                           WOLFSSL_ASN1_GENERALIZEDTIME*);
    void               wolfSSL_ASN1_TIME_free(WOLFSSL_ASN1_TIME*);
    int                wolfSSL_ASN1_TIME_get_length(WOLFSSL_ASN1_TIME*);
    unsigned char*     wolfSSL_ASN1_TIME_get_data(WOLFSSL_ASN1_TIME*);
    int                wolfSSL_ASN1_STRING_to_UTF8(unsigned char **, 
                           WOLFSSL_ASN1_STRING*);

    /*
     * Misc.
     */
    int           wolfSSL_library_init(void);
    const char*   wolfSSL_alert_type_string_long(int);
    const char*   wolfSSL_alert_desc_string_long(int);
    unsigned long wolfSSL_ERR_get_error(void);
    const char*   wolfSSL_ERR_reason_error_string(unsigned long);
    int           wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT*);
    const char*   wolfSSL_OBJ_nid2sn(int n);
    int           wolfSSL_OBJ_txt2nid(const char*);
"""

for func in optional_funcs:
    cdef += "{};".format(func.native_sig)

ffi_cdef = cdef + openssl.construct_cdef(optional_funcs, OLDTLS_ENABLED)
ffi.cdef(ffi_cdef)

if __name__ == "__main__":
    ffi.compile(verbose=True)

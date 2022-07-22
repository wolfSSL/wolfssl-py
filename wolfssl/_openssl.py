# -*- coding: utf-8 -*-
#
# _openssl.py
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

source = """
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/asn_public.h>
    #include <wolfssl/openssl/ssl.h>
    #include <wolfssl/openssl/x509v3.h>
    #include <wolfssl/openssl/opensslv.h>
    #include <wolfssl/openssl/crypto.h>
"""

def construct_cdef(optional_funcs, OLDTLS_ENABLED):
    cdef = """
        /**
         * Constants
         */
        static const long OPENSSL_VERSION_NUMBER;
        static const long SSLEAY_VERSION;

        static const long SSL_FILETYPE_PEM;
        static const long SSL_FILETYPE_ASN1;

        static const long EVP_PKEY_RSA;
        static const long EVP_PKEY_DSA;
        static const long EVP_PKEY_DH;
        static const long EVP_PKEY_EC;

        static const long GEN_EMAIL;
        static const long GEN_DNS;
        static const long GEN_URI;

        static const long X509_V_FLAG_CRL_CHECK;
        static const long X509_V_FLAG_CRL_CHECK_ALL;
        static const long X509_V_OK;

        static const long SSL_SENT_SHUTDOWN;
        static const long SSL_RECEIVED_SHUTDOWN;

        static const long SSL_OP_NO_SSLv2;
        static const long SSL_OP_NO_SSLv3;
        static const long SSL_OP_NO_TLSv1;
        static const long SSL_OP_NO_TLSv1_1;
        static const long SSL_OP_NO_TLSv1_2;
        static const long SSL_OP_NO_TLSv1_3;
        static const long SSL_MODE_RELEASE_BUFFERS;
        static const long SSL_OP_SINGLE_DH_USE;
        static const long SSL_OP_SINGLE_ECDH_USE;
        static const long SSL_OP_EPHEMERAL_RSA;
        static const long SSL_OP_MICROSOFT_SESS_ID_BUG;
        static const long SSL_OP_NETSCAPE_CHALLENGE_BUG;
        static const long SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
        static const long SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG;
        static const long SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER;
        static const long SSL_OP_MSIE_SSLV2_RSA_PADDING;
        static const long SSL_OP_SSLEAY_080_CLIENT_DH_BUG;
        static const long SSL_OP_TLS_D5_BUG;
        static const long SSL_OP_TLS_BLOCK_PADDING_BUG;
        static const long SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
        static const long SSL_OP_CIPHER_SERVER_PREFERENCE;
        static const long SSL_OP_TLS_ROLLBACK_BUG;
        static const long SSL_OP_PKCS1_CHECK_1;
        static const long SSL_OP_PKCS1_CHECK_2;
        static const long SSL_OP_NETSCAPE_CA_DN_BUG;
        static const long SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG;
        static const long SSL_OP_NO_COMPRESSION;
        static const long SSL_OP_NO_QUERY_MTU;
        static const long SSL_OP_COOKIE_EXCHANGE;
        static const long SSL_OP_NO_TICKET;
        static const long SSL_OP_ALL;
        static const long SSL_VERIFY_PEER;
        static const long SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        static const long SSL_VERIFY_CLIENT_ONCE;
        static const long SSL_VERIFY_NONE;
        static const long SSL_SESS_CACHE_OFF;
        static const long SSL_SESS_CACHE_CLIENT;
        static const long SSL_SESS_CACHE_SERVER;
        static const long SSL_SESS_CACHE_BOTH;
        static const long SSL_SESS_CACHE_NO_AUTO_CLEAR;
        static const long SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;
        static const long SSL_SESS_CACHE_NO_INTERNAL_STORE;
        static const long SSL_SESS_CACHE_NO_INTERNAL;
        static const long SSL_ST_CONNECT;
        static const long SSL_ST_ACCEPT;
        static const long SSL_ST_MASK;
        static const long SSL_CB_LOOP;
        static const long SSL_CB_EXIT;
        static const long SSL_CB_READ;
        static const long SSL_CB_WRITE;
        static const long SSL_CB_ALERT;
        static const long SSL_CB_READ_ALERT;
        static const long SSL_CB_WRITE_ALERT;
        static const long SSL_CB_ACCEPT_LOOP;
        static const long SSL_CB_ACCEPT_EXIT;
        static const long SSL_CB_CONNECT_LOOP;
        static const long SSL_CB_CONNECT_EXIT;
        static const long SSL_CB_HANDSHAKE_START;
        static const long SSL_CB_HANDSHAKE_DONE;
        static const long SSL_MODE_ENABLE_PARTIAL_WRITE;
        static const long SSL_MODE_AUTO_RETRY;
        static const long SSL_ERROR_WANT_READ;
        static const long SSL_ERROR_WANT_WRITE;
        static const long SSL_ERROR_ZERO_RETURN;
        static const long SSL_ERROR_WANT_X509_LOOKUP;
        static const long SSL_ERROR_SYSCALL;
        static const long SSL_ERROR_NONE;

        static const long V_ASN1_GENERALIZEDTIME;

        static const int NID_undef;

        /**
         * Types
         */
        typedef ... SSL_CTX;
        typedef ... SSL;
        typedef ... SSL_METHOD;
        typedef ... X509;
        typedef ... X509_EXTENSION;
        typedef ... X509_STORE_CTX;
        typedef ... X509_NAME;
        typedef ... X509_NAME_ENTRY;
        typedef ... BIO;
        typedef ... BIO_METHOD;
        typedef ... ASN1_TIME;
        typedef ... ASN1_GENERALIZEDTIME;
        typedef ... ASN1_STRING;
        typedef ... ASN1_OCTET_STRING;
        typedef ... ASN1_OBJECT;

        typedef int (*SSL_verify_cb)(int, X509_STORE_CTX*);

        /**
         * ASN.1
         */
        int            ASN1_STRING_set_default_mask_asc(const char*);
        int            ASN1_STRING_length(ASN1_STRING*);
        int            ASN1_STRING_type(const ASN1_STRING*);
        unsigned char* ASN1_STRING_data(ASN1_STRING*);
        ASN1_TIME*     ASN1_TIME_to_generalizedtime(ASN1_TIME *t,
                           ASN1_GENERALIZEDTIME**);
        void           ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME*);
        void           ASN1_TIME_free(ASN1_TIME*);
        int            ASN1_STRING_to_UTF8(unsigned char**, ASN1_STRING*);

        /**
         * Memory
         */
        void OPENSSL_free(void*);

        /**
         * SSL/TLS Method functions
         */
        """

    if OLDTLS_ENABLED:
        cdef += """
        SSL_METHOD* TLSv1_1_server_method(void);
        SSL_METHOD* TLSv1_1_client_method(void);
        """

    cdef += """
        SSL_METHOD* TLSv1_2_server_method(void);
        SSL_METHOD* TLSv1_2_client_method(void);
        SSL_METHOD* TLSv1_3_server_method(void);
        SSL_METHOD* TLSv1_3_client_method(void);
        SSL_METHOD* SSLv23_server_method(void);
        SSL_METHOD* SSLv23_client_method(void);
        SSL_METHOD* SSLv23_method(void);
        """

    if OLDTLS_ENABLED:
        cdef += """
        SSL_METHOD* TLSv1_1_method(void);
        """

    cdef += """
        SSL_METHOD* TLSv1_2_method(void);
        SSL_METHOD* TLSv1_3_method(void);

        /**
         * SSL/TLS Context functions
         */
        SSL_CTX* SSL_CTX_new(SSL_METHOD*);
        void  SSL_CTX_free(SSL_CTX*);

        int  SSL_CTX_set_cipher_list(SSL_CTX*, const char*);
        int  SSL_CTX_use_PrivateKey_file(SSL_CTX*, const char*, int);
        int  SSL_CTX_load_verify_locations(SSL_CTX*, const char*, const char*);
        void SSL_CTX_set_verify(SSL_CTX*, int, SSL_verify_cb);
        void SSL_CTX_set_verify_depth(SSL_CTX*, int);
        int  SSL_CTX_get_verify_mode(const SSL_CTX*);
        int  SSL_CTX_use_certificate_file(SSL_CTX*, const char*, int);
        int  SSL_CTX_use_certificate_chain_file(SSL_CTX*, const char*);
        long SSL_CTX_get_options(SSL_CTX*);
        long SSL_CTX_set_options(SSL_CTX*, long);
        void SSL_CTX_set_default_passwd_cb(SSL_CTX*, pem_password_cb*);
        void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX*, void*);
        void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX*, int (*)(SSL*,
                const unsigned char **, unsigned int*, void*), void*);
        void SSL_CTX_set_next_proto_select_cb(SSL_CTX*, int (*)(SSL*, unsigned char**,
                unsigned char*, const unsigned char*, unsigned int, void*), void*);
        int  SSL_CTX_set_alpn_protos(SSL_CTX*, const unsigned char*, unsigned int);
        void SSL_CTX_set_alpn_select_cb(SSL_CTX*, int (*)(SSL*,
                const unsigned char**, unsigned char*, const unsigned char*,
                unsigned int, void*), void*);
        int  SSL_CTX_set_tlsext_servername_callback(SSL_CTX*, CallbackSniRecv);
        long SSL_CTX_set_mode(SSL_CTX*, long);

        /**
         * SSL/TLS Session functions
         */
        SSL*          SSL_new(SSL_CTX*);
        void          SSL_free(SSL*);
        int           SSL_set_fd(SSL*, int);
        int           SSL_get_error(SSL*, int);
        char*         ERR_error_string(int, char*);
        int           SSL_connect(SSL*);
        int           SSL_accept(SSL*);
        int           SSL_write(SSL*, const void*, int);
        int           SSL_read(SSL*, void*, int);
        int           SSL_peek(SSL*, void*, int);
        int           SSL_pending(SSL*);
        int           SSL_shutdown(SSL*);
        void          SSL_set_shutdown(SSL*, int);
        int           SSL_get_shutdown(const SSL*);
        X509*         SSL_get_peer_certificate(SSL*);
        const char*   SSL_alert_type_string_long(int);
        const char*   SSL_alert_desc_string_long(int);
        int           SSL_renegotiate(SSL*);
        void          SSL_get0_next_proto_negotiated(const SSL*,
                          const unsigned char**, unsigned*);
        const char*   SSL_get_servername(SSL*, unsigned char);
        int           SSL_set_tlsext_host_name(SSL*, const char*);
        int           SSL_set_alpn_protos(SSL*, const unsigned char*, unsigned int);
        void          SSL_get0_alpn_selected(const SSL*, const unsigned char**,
                          unsigned int*);
        unsigned long SSL_set_mode(SSL*, unsigned long);
        void          SSL_set_connect_state(SSL*);

        /**
         * X509 functions
         */
        X509*              X509_STORE_CTX_get_current_cert(X509_STORE_CTX*);
        int                X509_up_ref(X509*);
        void               X509_free(X509*);
        int                X509_STORE_CTX_get_error(X509_STORE_CTX*);
        int                X509_STORE_CTX_get_error_depth(X509_STORE_CTX*);
        int                SSL_get_ex_data_X509_STORE_CTX_idx(void);
        void*              X509_STORE_CTX_get_ex_data(X509_STORE_CTX*, int);
        void               X509_STORE_CTX_set_error(X509_STORE_CTX*, int);
        X509_NAME*         X509_get_subject_name(X509*);
        char*              X509_NAME_oneline(X509_NAME*, char*, int);
        ASN1_TIME*         X509_get_notBefore(const X509*);
        ASN1_TIME*         X509_get_notAfter(const X509*);
        int                X509_NAME_entry_count(X509_NAME*);
        X509_NAME_ENTRY*   X509_NAME_get_entry(X509_NAME*, int);
        ASN1_OBJECT*       X509_NAME_ENTRY_get_object(X509_NAME_ENTRY*);
        ASN1_STRING*       X509_NAME_ENTRY_get_data(X509_NAME_ENTRY*);
        int                X509_NAME_get_index_by_NID(X509_NAME*, int, int);
        int                X509_NAME_cmp(const X509_NAME*, const X509_NAME*);
        int                X509_get_ext_count(const X509 *x);
        X509_EXTENSION*    X509_get_ext(const X509*, int loc);
        void               X509_EXTENSION_free(X509_EXTENSION*);
        ASN1_OBJECT*       X509_EXTENSION_get_object(X509_EXTENSION*);
        ASN1_OCTET_STRING* X509_EXTENSION_get_data(X509_EXTENSION*);
        X509*              X509_dup(X509*);

        /**
         * BIO functions
         */
        BIO* BIO_new(BIO_METHOD*);
        BIO_METHOD* BIO_s_mem(void);

        /**
         * Misc.
         */
        int           OpenSSL_add_all_algorithms(void);
        void          SSL_load_error_strings(void);
        int           SSL_library_init(void);
        unsigned long ERR_get_error(void);
        const char*   ERR_reason_error_string(unsigned long);
        int           OBJ_obj2nid(const ASN1_OBJECT*);
        const char*   OBJ_nid2sn(int n);
        int           OBJ_txt2nid(const char*);
    """

    for func in optional_funcs:
        cdef += "{};".format(func.ossl_sig)

    return cdef

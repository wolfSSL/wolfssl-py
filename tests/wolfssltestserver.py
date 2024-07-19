from wolfssl import SSLContext, PROTOCOL_TLS, CERT_NONE
from socketserver import TCPServer, BaseRequestHandler

ca_path = './certs/client-cert.pem'
cert_path = './certs/server-cert.pem'
key_path = './certs/server-key.pem'

class wolfSSLTestServer(TCPServer):
    class wolfSSLRequestHandler(BaseRequestHandler):
        def handle(self):
            ssl_socket = self.server.ctx.wrap_socket(self.request, server_side=True)
            ssl_socket.recv(1024)
            ssl_socket.sendall(b'I hear you fa shizzle!')
    ctx = None
    def __init__(self, address, version=PROTOCOL_TLS, ca=ca_path, cert=cert_path, key=key_path, verify=CERT_NONE):
        TCPServer.__init__(self, address, self.wolfSSLRequestHandler, bind_and_activate=False)
        self.allow_reuse_address = self.allow_reuse_port = True
        self.ctx = SSLContext(version, server_side=True)
        self.ctx.verify_mode = verify
        self.ctx.load_verify_locations(ca)
        self.ctx.load_cert_chain(cert, key)
        self.port = address[1]
        self.version = version
        self.server_bind()
        self.server_activate()

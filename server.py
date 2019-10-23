import socket
import sys
import threading

from fernet import password_decrypt


class Server:

    def __init__(self, ip, port):
        self.server_address = ip
        self.server_port = port

    def read_received_bytes(self, received_bytes: bytes) -> str:
        result: str
        if len(sys.argv) == 5:
            from cryptography.fernet import InvalidToken
            try:
                result = password_decrypt(received_bytes, sys.argv[4].encode('utf-8')).decode('utf-8')
            except InvalidToken:
                result = "???"
        else:
            result = received_bytes.decode('utf-8')
        return result


class TCPServer(Server):

    def __init__(self, ip, port):
        super().__init__(ip, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.server_address, self.server_port))
        self.server_socket.listen(5)
        print("TCP Server waiting for connections on port 9999")

    def handle_client(self, client_socket):
        while True:
            received_bytes = client_socket.recv(1024)
            print("[*] Received: %s" % self.read_received_bytes(received_bytes))
            client_socket.send("message received".encode('utf8'))

    def listen(self):
        while True:
            client, addr = self.server_socket.accept()
            print("Accepted connection from %s" % addr[0])
            client_handler = threading.Thread(target=self.handle_client, args=(client,))
            client_handler.start()


class UDPServer(Server):

    def __init__(self, ip, port):
        super().__init__(ip, port)
        self.buffer = 4096
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((self.server_address, self.server_port))
        print("UDP Server listening on port %s" % self.server_port)

    def listen(self):
        while True:
            data, address = self.server_socket.recvfrom(self.buffer)
            data = data.strip()
            print("RCVD: %s" % self.read_received_bytes(data))


if sys.argv[1] == "udp":
    udp_server = UDPServer(sys.argv[2], int(sys.argv[3]))
    udp_server.listen()
elif sys.argv[1] == "tcp":
    tcp_server = TCPServer(sys.argv[2], int(sys.argv[3]))
    tcp_server.listen()


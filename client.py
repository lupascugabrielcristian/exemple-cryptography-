import sys
import socket

from fernet import password_encrypt

# Use exeples
# python3.7 server.py udp 192.168.1.110 999
# python3.7 client.py tcp 192.168.1.110 999

class Client:

    def __init__(self, ip, port):
        self.server_address = ip
        self.server_port = port
        if len(sys.argv) == 5:
            print("Encrypting user messages")
        else:
            print("Not encrypting")

    def get_bytes_to_send(self) -> bytes:
        message = input("[>] ").strip()
        if message == "break":
            result = None
        elif len(sys.argv) == 5:
            # python3.7 server.py tcp 192.168.56.1 9999 abct
            result = password_encrypt(message.encode('utf-8'), sys.argv[4].encode('utf-8'))
        else:
            result = message.encode('utf8')
        return result


class TCPClient(Client):

    def __init__(self, ip, port):
        super().__init__(ip, port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.server_address, self.server_port))
        print("Client connected")

    def send(self):
        while True:
            bytes_to_send = self.get_bytes_to_send()
            if bytes is None:
                break
            else:
                self.client_socket.send(bytes_to_send)
        self.client_socket.close()


class UDPClient(Client):

    def __init__(self, ip, port):
        super().__init__(ip, port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.buffer = 4096
        self.server_udp_address = (self.server_address, self.server_port)

    def send(self):
        while True:
            bytes_to_send = self.get_bytes_to_send()
            self.client_socket.sendto(bytes_to_send, self.server_udp_address)
            response, address = self.client_socket.recvfrom(self.buffer)
            print("%s" % response.decode('utf8'))


if sys.argv[1] == "udp":
    udp_client = UDPClient(sys.argv[2], int(sys.argv[3]))
    udp_client.send()
elif sys.argv[1] == "tcp":
    tcp_client = TCPClient(sys.argv[2], int(sys.argv[3]))
    tcp_client.send()

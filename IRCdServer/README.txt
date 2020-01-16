IRC Covert Channel IRCd Server Readme

Status: Contains an unrealircd.conf file as an example. In it, I have commented out logging of operators and auto-joining them to an oper channel.
	This prevents some detection when making yourself an operator.
	I have also added an operclass called c2bot that disables artificial lag for operatiors and an oper block called bot with the password bot.
	Please read entire config and update values as needed (i.e. LtDan). In this example the OP_NICK and OP_PASS would be 'bot'
	If the covert channel needs to send data faster than the lag allows you will need to have them become operators. To do this you will need 
	to edit the IRCd server config to allow for this by creating an operator class and password for them to use. This can be done with an 
	IRCd implant that can edit the config and "rehash" or reload it in the server.
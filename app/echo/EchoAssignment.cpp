#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {
  // Your server code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for serverMain.

  const int BUFFUER_SIZE = 1024;
  const int LISTEN_BACKLOG = 64;
  sockaddr_in server_addr, client_addr;
  socklen_t server_addr_len, client_addr_len;
  int server_sock_fd, client_sock_fd, syscall_result;
  char buff[BUFFUER_SIZE], server_ip[INET_ADDRSTRLEN], client_ip[INET_ADDRSTRLEN], answer[BUFFUER_SIZE];

  server_sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, bind_ip, &(server_addr.sin_addr));
  server_addr.sin_port = htons(port);

  if ((syscall_result = bind(server_sock_fd, (struct sockaddr*) &server_addr, sizeof(server_addr))) == -1) {
    return syscall_result;
  }
  if ((syscall_result = listen(server_sock_fd, 64)) == -1) {
    return syscall_result;
  }

  while (true) {
    server_addr_len = sizeof(server_addr);
    if ((client_sock_fd = accept(server_sock_fd, (struct sockaddr*) &server_addr, &server_addr_len)) == -1) {
      return client_sock_fd;
    }
    client_addr_len = sizeof(client_addr);
    if ((syscall_result = getpeername(client_sock_fd, (struct sockaddr*) &client_addr, &client_addr_len)) == -1) {
      return syscall_result;
    }
    strcpy(client_ip, inet_ntoa(client_addr.sin_addr));

    if ((syscall_result = getsockname(client_sock_fd, (struct sockaddr*) &server_addr, &server_addr_len)) == -1) {
      return syscall_result;
    }
    strcpy(server_ip, inet_ntoa(server_addr.sin_addr));

    memset(&buff, 0, sizeof(buff));
    if ((syscall_result = read(client_sock_fd, buff, BUFFUER_SIZE)) == -1) {
      return syscall_result;
    }

    buff[strlen(buff) + 1] = 0;
    submitAnswer(client_ip, buff);

    memset(answer, 0, sizeof(answer));
    if (!strcmp("whoru", buff)) {
      strcpy(answer, server_ip);
    }
    else if (!strcmp("whoami", buff)) {
      strcpy(answer, client_ip);
    }
    else if (!strcmp("hello", buff)) {
      strcpy(answer, server_hello);
    }
    else {
      strcpy(answer, buff);
    }
    answer[strlen(answer) + 1] = '\n';

    if ((syscall_result = write(client_sock_fd, answer, strlen(answer) + 2)) == -1) {
      return syscall_result;
    }
  }
  close(server_sock_fd);
  
  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.

  const int BUFFUER_SIZE = 1024;
  sockaddr_in server_addr;
  int socket_fd, syscall_result;
  char buff[BUFFUER_SIZE], command_to_server[strlen(command) + 2];

  if ((socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
    return socket_fd;
  }
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, server_ip, &(server_addr.sin_addr));
  server_addr.sin_port = htons(port);

  if ((syscall_result = connect(socket_fd, (struct sockaddr*) &server_addr, sizeof(server_addr))) == -1) {
    return syscall_result;
  }

  memset(command_to_server, 0, sizeof(command_to_server));
  strcpy(command_to_server, command);
  command_to_server[strlen(command) + 1] = '\n';
  if ((syscall_result = write(socket_fd, command_to_server, sizeof(command_to_server))) == -1) {
    return syscall_result;
  }

  memset(&buff, 0, sizeof(buff));
  if ((syscall_result = read(socket_fd, buff, BUFFUER_SIZE)) == -1) {
    return syscall_result;
  }
  buff[strlen(buff) + 1] = 0;
  submitAnswer(server_ip, buff);

  if ((syscall_result = close(socket_fd)) == -1) {
    return syscall_result;
  }
  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {

  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}

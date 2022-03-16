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

  // TODO: 에러 핸들링

  sockaddr_in server_addr, client_addr;
  int server_sock_fd, client_sock_fd, err;
  socklen_t client_addr_len;
  char *buff, client_ip[INET_ADDRSTRLEN];

  server_sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  memset(&server_addr, 0, sizeof(sockaddr));
  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, bind_ip, &(server_addr.sin_addr));
  server_addr.sin_port = htons(port);

  err = bind(server_sock_fd, (struct sockaddr*) &server_addr, sizeof(server_addr));
  if (err < 0) {
    printf("%s\n", strerror(err));
    exit(-1);
  }

  listen(server_sock_fd, 5);

  client_addr_len = sizeof(client_addr);
  client_sock_fd = accept(server_sock_fd, (struct sockaddr*) &client_addr, &client_addr_len);
  if (client_sock_fd < 0) {
    printf("%s\n", strerror(client_sock_fd));
    return client_sock_fd;
  }

  buff = (char*) alloca(1024);
  read(client_sock_fd, buff, 1024);

  buff[1024] = '\0';
  inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
  submitAnswer(client_ip, buff);

  write(client_sock_fd, "hello\n", 6);

  close(server_sock_fd);
  
  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.

  sockaddr_in server_addr;
  int socket_fd;
  char* buff;

  socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  memset(&server_addr, 0, sizeof(sockaddr));
  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, server_ip, &(server_addr.sin_addr));
  server_addr.sin_port = htons(port);

  connect(socket_fd, (struct sockaddr*) &server_addr, sizeof(server_addr));

  write(socket_fd, command, strlen(command));

  buff = (char*) alloca(1024);
  read(socket_fd, buff, 1024);

  buff[1024] = '\0';
  submitAnswer(server_ip, buff);

  close(socket_fd);

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

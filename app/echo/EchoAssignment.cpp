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
  int server_sock_fd, client_sock_fd, err, input_len;
  socklen_t client_addr_len;
  char buff[1024], server_ip[INET_ADDRSTRLEN], client_ip[INET_ADDRSTRLEN], *answer;

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

  client_addr_len = sizeof(struct sockaddr_in);
  getpeername(client_sock_fd, (struct sockaddr*) &client_addr, &client_addr_len);
  getsockname(server_sock_fd, (struct sockaddr*) &server_addr, &client_addr_len);
  strcpy(client_ip, inet_ntoa(client_addr.sin_addr));
  strcpy(server_ip, inet_ntoa(server_addr.sin_addr));

  memset(&buff, (int)'\0', sizeof(buff));
  read(client_sock_fd, buff, 1024);
  input_len = strlen(buff);

  submitAnswer(client_ip, buff);

  if (!strcmp("whoru", buff)) {
    write(client_sock_fd, server_ip, sizeof(server_ip)); 
  }
  else if (!strcmp("whoami", buff)) {
    write(client_sock_fd, client_ip, sizeof(client_ip));
  }
  else if (!strcmp("hello", buff)) {
    write(client_sock_fd, server_hello, strlen(server_hello) + 1);
  }
  else {
    // docs에는 \0로 끝내라 하는데 \0로 끝내야 제대로 인식됨. 확인 필요.
    write(client_sock_fd, buff, input_len + 1);
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
  char buff[BUFFUER_SIZE];

  if ((socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
    return socket_fd;
  }
  memset(&server_addr, 0, sizeof(sockaddr));
  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, server_ip, &(server_addr.sin_addr));
  server_addr.sin_port = htons(port);

  if ((syscall_result = connect(socket_fd, (struct sockaddr*) &server_addr, sizeof(server_addr))) == -1) {
    return syscall_result;
  }
  if ((syscall_result = write(socket_fd, command, strlen(command))) == -1) {
    return syscall_result;
  }
  if ((syscall_result = read(socket_fd, buff, BUFFUER_SIZE)) == -1) {
    return syscall_result;
  }
  // submitAnswer ending charater 설정 필요할듯?
  // buff[1024] = '\0';
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

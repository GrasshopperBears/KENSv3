/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {}

struct sock_table_item {
  int pid;
  int fd;
  struct kens_sockaddr_in* sockaddr;
};

std::vector<sock_table_item*> sock_table;
using sock_table_item_itr = typename std::vector<struct sock_table_item*>::iterator;

struct kens_sockaddr_in {
  __uint8_t sin_len;
  sa_family_t sin_family;
  in_port_t sin_port;
  uint32_t sin_addr;
};

sock_table_item_itr find_sock_alloc_item(int pid, int fd) {
  sock_table_item_itr itr;
  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    if ((*itr)->pid == pid && (*itr)->fd == fd) { break; }
  }
  return itr;
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  (void)syscallUUID;
  (void)pid;

  int fd;

  switch (param.syscallNumber) {
  case SOCKET: {
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    struct sock_table_item* sock_table_item = (struct sock_table_item*) malloc(sizeof(struct sock_table_item));
    if (sock_table_item == NULL) {
      printf("Error: can't allocate memory(sock_table_item)\n");
      returnSystemCall(syscallUUID, -1);
    }

    fd = createFileDescriptor(pid);

    sock_table_item->sockaddr = NULL;
    sock_table_item->fd = fd;
    sock_table_item->pid = pid;
    sock_table.push_back(sock_table_item);

    returnSystemCall(syscallUUID, fd);
    break;
  }
  case CLOSE: {
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    fd = std::get<int>(param.params[0]);
    sock_table_item_itr sock_table_item_itr = find_sock_alloc_item(pid, fd);

    if (sock_table_item_itr == sock_table.end()) {
      returnSystemCall(syscallUUID, -1);
      break;
    }
    struct sock_table_item* sock_table_item = *sock_table_item_itr;

    removeFileDescriptor(pid, fd);

    if (sock_table_item->sockaddr != NULL)
      free(sock_table_item->sockaddr);
    free(sock_table_item);
    sock_table.erase(sock_table_item_itr);

    returnSystemCall(syscallUUID, 0);
    break;
  }
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  case CONNECT:
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND: {
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    const in_addr_t NL_INADDR_ANY = htonl(INADDR_ANY);
    int param_fd = std::get<int>(param.params[0]);
    struct sockaddr_in *param_addr = 
      (struct sockaddr_in *)(static_cast<struct sockaddr *>(std::get<void *>(param.params[1])));
    sock_table_item_itr findItr;
    sock_table_item_itr itr;
    bool isFind = false;

    for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
      /*
        Consider Overlap
        - "Diff Addr and Same Port" is allowed.
        - "INADDR_ANY Addr and Same Port" is not allowed.
      */
      if ((*itr)->sockaddr != NULL && (
        (*itr)->sockaddr->sin_addr == param_addr->sin_addr.s_addr || 
        param_addr->sin_addr.s_addr == NL_INADDR_ANY ||
        (*itr)->sockaddr->sin_addr == NL_INADDR_ANY)
      ) {
        if ((*itr)->sockaddr->sin_port == param_addr->sin_port) {
          returnSystemCall(syscallUUID, -1);
        }
      }
      // Find same pid, same fd.
      if ((*itr)->pid == pid && (*itr)->fd == param_fd) {
        findItr = itr;
        isFind = true;
      }
    }

    // Prevent Closed sockets or unexisted sockets.
    if (!isFind)
      returnSystemCall(syscallUUID, -1);

    struct sock_table_item* sock_table_item = *findItr;
    // Prevent Double Bind. If it is already bound, return -1. ("Same addr and Diff port" is not allowed.)
    if (sock_table_item->sockaddr != NULL) {
      returnSystemCall(syscallUUID, -1);
    }

    struct kens_sockaddr_in* addr = (struct kens_sockaddr_in *) malloc(sizeof(struct kens_sockaddr_in));
    if (sock_table_item == NULL) {
      printf("Error: can't allocate memory(sockaddr_in)\n");
      returnSystemCall(syscallUUID, -1);
    }

    addr->sin_len = sizeof(param_addr->sin_addr);
    addr->sin_family = param_addr->sin_family;
    addr->sin_port = param_addr->sin_port;
    addr->sin_addr = param_addr->sin_addr.s_addr;
    sock_table_item->sockaddr = addr;

    returnSystemCall(syscallUUID, 0);
    break;
  }
  case GETSOCKNAME: {
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    fd = std::get<int>(param.params[0]);
    struct sockaddr_in* addr = (struct sockaddr_in *) static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    socklen_t* addrlen = static_cast<socklen_t *>(std::get<void *>(param.params[2]));
    sock_table_item_itr found_item_itr = find_sock_alloc_item(pid, fd);

    if (found_item_itr == sock_table.end()) {
      returnSystemCall(syscallUUID, -1);
      break;
    }
    struct kens_sockaddr_in* sockaddr_in = (*found_item_itr)->sockaddr;

    addr->sin_addr.s_addr = sockaddr_in->sin_addr;
    addr->sin_family = sockaddr_in->sin_family;
    addr->sin_port = sockaddr_in->sin_port;
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));

    *addrlen = sockaddr_in->sin_len;
    returnSystemCall(syscallUUID, 0);

    break;
  }
  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E

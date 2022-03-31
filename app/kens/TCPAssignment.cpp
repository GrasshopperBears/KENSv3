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

// ------------------enums start------------------
enum Status {
  CLOSED,
  LISTEN,
  SYN_RCVD,
  SYN_SENT,
  ESTAB
};

enum TimerType {
  ACCEPT
};
// ------------------enums end------------------

// ----------------structs start----------------
struct sock_info {
  int pid;
  int fd;   // -1 if not returned yet
  struct sock_info* parent_sock;
  struct kens_sockaddr_in* my_sockaddr;
  struct kens_sockaddr_in* peer_sockaddr;
  std::list<sock_info*>* child_sock_list;
  enum Status status;
  int backlog;
  int current_backlog;
};

struct kens_sockaddr_in {
  __uint8_t sin_len;
  sa_family_t sin_family;
  in_port_t sin_port;
  uint32_t sin_addr;
};

struct TimerPayload {
  UUID syscallUUID;
  int pid;
  SystemCallInterface::SystemCallParameter *param;
  TimerType timerType;
};
// ----------------structs end----------------

const int PACKET_OFFSET = 14;
const int SEGMENT_OFFSET = PACKET_OFFSET + 20;

std::list<sock_info*> sock_table;
std::list<UUID> accept_wait_timers;
std::map<UUID, bool> syscall_set;
using sock_info_itr = typename std::list<struct sock_info*>::iterator;

sock_info_itr find_sock_info(int pid, int fd) {
  sock_info_itr itr;
  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    if ((*itr)->pid == pid && (*itr)->fd == fd) { break; }
  }
  return itr;
}

void TCPAssignment::acceptHandler(UUID syscallUUID, int pid,
                                  SystemCallInterface::SystemCallParameter *param) {
  int fd = std::get<int>(param->params[0]);
  struct sockaddr_in* param_addr = (struct sockaddr_in *) static_cast<struct sockaddr *>(std::get<void *>(param->params[1]));
  socklen_t* addrlen = static_cast<socklen_t *>(std::get<void *>(param->params[2]));

  struct sock_info *sock_info, *sock_info_in_backlog = NULL, *parent_sock_info;
  sock_info_itr itr;
  std::map<UUID, bool>::iterator syscall_itr = syscall_set.find(syscallUUID);
  // bool flag = false;
  bool syscall_returned = syscall_itr->second;

  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    sock_info = *itr;
    // only for proper pid and fd
    if (sock_info->pid == pid && sock_info->parent_sock != NULL && sock_info->parent_sock->fd == fd) {
      // flag = true;
      parent_sock_info = sock_info;
      if (sock_info->status == Status::ESTAB && sock_info->fd < 0) {
        // sock_info_in_backlog = *itr;
        break;
      } else if (sock_info->status == Status::SYN_RCVD) {
        // flag = true;
        break;
      }
    } else if (sock_info->pid == pid && sock_info->fd == fd) {
      parent_sock_info = sock_info;
    }
  }

  // No socket is established or syn recieved
  if (itr == sock_table.end() && syscall_returned) {
    free(param);
    syscall_set.insert(std::make_pair(syscallUUID, true));
    printf("accept error 2\n");
    returnSystemCall(syscallUUID, -1);
    return;
  }
  if (sock_info->status == Status::ESTAB && sock_info->fd < 0) {
    sock_info->fd = createFileDescriptor(sock_info->pid);

    param_addr->sin_addr.s_addr = sock_info->peer_sockaddr->sin_addr;
    param_addr->sin_family = sock_info->peer_sockaddr->sin_family;
    param_addr->sin_port = sock_info->peer_sockaddr->sin_port;

    // TODO: set addrlen

    free(param);
    syscall_set.insert(std::make_pair(syscallUUID, true));
    printf("returned\n");
    returnSystemCall(syscallUUID, sock_info->fd);
    return;
  }
  if (sock_info->status == Status::SYN_RCVD || (!syscall_returned && sock_info->child_sock_list->size() < sock_info->backlog)) {
    struct TimerPayload *payload = (struct TimerPayload*) malloc(sizeof(struct TimerPayload));
    payload->syscallUUID = syscallUUID;
    payload->pid = pid;
    payload->param = param;
    payload->timerType = TimerType::ACCEPT;

    UUID timerId = addTimer(payload, 2000);   // 2ms
    accept_wait_timers.push_back(timerId);
    return;
  }
  free(param);
  syscall_set.insert(std::make_pair(syscallUUID, true));
  printf("accept error 3, %d/%d\n", sock_info->child_sock_list->size(), sock_info->backlog);
  returnSystemCall(syscallUUID, -1);
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {
  switch (param.syscallNumber) {
  case SOCKET: {
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    struct sock_info* sock_info = (struct sock_info*) malloc(sizeof(struct sock_info));
    if (sock_info == NULL) {
      printf("Error: can't allocate memory(sock_info)\n");
      returnSystemCall(syscallUUID, -1);
      break;
    }

    int fd = createFileDescriptor(pid);

    sock_info->my_sockaddr = NULL;
    sock_info->peer_sockaddr = NULL;
    sock_info->fd = fd;
    sock_info->pid = pid;
    sock_info->status = Status::CLOSED;
    sock_info->parent_sock = NULL;
    sock_info->child_sock_list = new std::list<struct sock_info*>();
    sock_table.push_back(sock_info);

    returnSystemCall(syscallUUID, fd);
    break;
  }
  case CLOSE: {
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    int fd = std::get<int>(param.params[0]);
    sock_info_itr sock_info_itr = find_sock_info(pid, fd);

    if (sock_info_itr == sock_table.end()) {
      returnSystemCall(syscallUUID, -1);
      break;
    }
    struct sock_info* sock_info = *sock_info_itr;

    removeFileDescriptor(pid, fd);

    sock_table.erase(sock_info_itr);
    if (sock_info->my_sockaddr != NULL)
      free(sock_info->my_sockaddr);
    if (sock_info->peer_sockaddr != NULL)
      free(sock_info->peer_sockaddr);
    free(sock_info);

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
  case LISTEN: {
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    int fd = std::get<int>(param.params[0]);
    int backlog = std::get<int>(param.params[1]);
    
    sock_info_itr sock_info_itr = find_sock_info(pid, fd);
    struct sock_info* sock_info = *sock_info_itr;

    if (sock_info_itr == sock_table.end() || sock_info->status == Status::LISTEN) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    if (backlog < 0) {
      sock_info->backlog = 0;
    } else if (backlog > SOMAXCONN) {
      sock_info->backlog = SOMAXCONN;
    } else {
      sock_info->backlog = backlog;
    }
    sock_info->status = Status::LISTEN;
    printf("listening...........\n");
    sock_info->current_backlog = 0;

    returnSystemCall(syscallUUID, 0);
    break;
  }
  case ACCEPT: {
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    SystemCallParameter *param_to_pass = (SystemCallParameter *) malloc(sizeof(SystemCallParameter));
    memcpy(param_to_pass, &param, sizeof(SystemCallParameter));
    syscall_set.insert(std::make_pair(syscallUUID, false));
    printf("accept call: %d\n", syscallUUID);
    acceptHandler(syscallUUID, pid, param_to_pass);
    break;
  }
  case BIND: {
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    const in_addr_t NL_INADDR_ANY = htonl(INADDR_ANY);
    int param_fd = std::get<int>(param.params[0]);
    struct sockaddr_in *param_addr = 
      (struct sockaddr_in *)(static_cast<struct sockaddr *>(std::get<void *>(param.params[1])));
    sock_info_itr findItr;
    sock_info_itr itr;
    bool isFind = false;

    for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
      /*
        Consider Overlap
        - "Diff Addr and Same Port" is allowed.
        - "INADDR_ANY Addr and Same Port" is not allowed.
      */
      if ((*itr)->my_sockaddr != NULL && (
        (*itr)->my_sockaddr->sin_addr == param_addr->sin_addr.s_addr || 
        param_addr->sin_addr.s_addr == NL_INADDR_ANY ||
        (*itr)->my_sockaddr->sin_addr == NL_INADDR_ANY)
      ) {
        if ((*itr)->my_sockaddr->sin_port == param_addr->sin_port) {
          returnSystemCall(syscallUUID, -1);
          break;
        }
      }
      // Find same pid, same fd.
      if ((*itr)->pid == pid && (*itr)->fd == param_fd) {
        findItr = itr;
        isFind = true;
      }
    }

    // Prevent Closed sockets or unexisted sockets.
    if (!isFind) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    struct sock_info* sock_info = *findItr;
    // Prevent Double Bind. If it is already bound, return -1. ("Same addr and Diff port" is not allowed.)
    if (sock_info->my_sockaddr != NULL) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    struct kens_sockaddr_in* addr = (struct kens_sockaddr_in *) malloc(sizeof(struct kens_sockaddr_in));
    if (sock_info == NULL) {
      printf("Error: can't allocate memory(sockaddr_in)\n");
      returnSystemCall(syscallUUID, -1);
      break;
    }

    addr->sin_len = sizeof(param_addr->sin_addr);
    addr->sin_family = param_addr->sin_family;
    addr->sin_port = param_addr->sin_port;
    addr->sin_addr = param_addr->sin_addr.s_addr;
    sock_info->my_sockaddr = addr;

    returnSystemCall(syscallUUID, 0);
    break;
  }
  case GETSOCKNAME: {
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    int fd = std::get<int>(param.params[0]);
    struct sockaddr_in* addr = (struct sockaddr_in *) static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    socklen_t* addrlen = static_cast<socklen_t *>(std::get<void *>(param.params[2]));
    sock_info_itr found_item_itr = find_sock_info(pid, fd);

    if (found_item_itr == sock_table.end()) {
      returnSystemCall(syscallUUID, -1);
      break;
    }
    struct kens_sockaddr_in* sockaddr_in = (*found_item_itr)->my_sockaddr;

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

void getPacketSrcDst(Packet *packet, uint32_t *src_ip, uint16_t *src_port, uint32_t *dst_ip, uint16_t *dst_port) {
  packet->readData(PACKET_OFFSET + 12, src_ip, 4);
  packet->readData(PACKET_OFFSET + 16, dst_ip, 4);
  packet->readData(SEGMENT_OFFSET, src_port, 2);
  packet->readData(SEGMENT_OFFSET + 2, dst_port, 2);
}

void setPacketSrcDst(Packet *packet, uint32_t *src_ip, uint16_t *src_port, uint32_t *dst_ip, uint16_t *dst_port) {
  packet->writeData(PACKET_OFFSET + 12, src_ip, 4);
  packet->writeData(PACKET_OFFSET + 16, dst_ip, 4);
  packet->writeData(SEGMENT_OFFSET, src_port, 2);
  packet->writeData(SEGMENT_OFFSET + 2, dst_port, 2);
}

bool isSynAckPacket(Packet *packet) {
  uint8_t flags = 0;
  packet->readData(SEGMENT_OFFSET + 13, &flags, 1);
  return ((flags >> 1) & 1) & ((flags >> 4) & 1);
}

bool isSynPacket(Packet *packet) {
  uint8_t flags = 0;
  packet->readData(SEGMENT_OFFSET + 13, &flags, 1);
  return (flags >> 1) & 1;
}

bool isAckPacket(Packet *packet) {
  uint8_t flags = 0;
  packet->readData(SEGMENT_OFFSET + 13, &flags, 1);
  return (flags >> 4) & 1;
}

void cloneSockInfo(struct sock_info* dst, struct sock_info* src) {
  dst->backlog = 0;
  dst->current_backlog = 0;
  dst->child_sock_list = new std::list<struct sock_info*>();
  dst->fd = -1;
  memcpy(dst->my_sockaddr, src->my_sockaddr, sizeof(struct kens_sockaddr_in));
  dst->parent_sock = src;
  dst->pid = src->pid;
  dst->status = Status::SYN_RCVD;
}


void TCPAssignment::handleSynAckPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  Packet response_packet = packet->clone();

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  // TODO: should be implemented
  setPacketSrcDst(&response_packet, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
  sendPacket("IPv4", std::move(response_packet));
  // return;
}

void TCPAssignment::handleSynPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  sock_info_itr itr;
  struct sock_info* sock_info;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  // TODO: 이미 ESTAB된 socket일 경우 데이터 주고받기

  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    sock_info = *itr;
    if (sock_info->my_sockaddr != NULL
        && (sock_info->my_sockaddr->sin_port == 0 || sock_info->my_sockaddr->sin_port == income_dst_port)
        && (sock_info->my_sockaddr->sin_addr == 0 || sock_info->my_sockaddr->sin_addr == income_dst_ip))
    {
      break;
    }
  }

  if (itr == sock_table.end()) {
    // printf("syn err 1\n");
    return;
  }

  // Server: initiallize TCP connection (1st step of 3-way handshake)
  if (sock_info->status == Status::LISTEN) {
    Packet response_packet = packet->clone();   // TODO: more than clone
    struct sock_info* new_sock_info;

    setPacketSrcDst(&response_packet, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
    
    // backlog count check
    if (sock_info->backlog <= sock_info->current_backlog) {
      // 무시 혹은 RST flag set
      // TODO: (maybe) clone한 패킷 처리?
      printf("overflow");
      return;
    }
    
    if ((new_sock_info = (struct sock_info*) malloc(sizeof(struct sock_info))) == NULL) {
      return;
    }
    new_sock_info->my_sockaddr = (struct kens_sockaddr_in *) malloc(sizeof(struct kens_sockaddr_in));
    new_sock_info->peer_sockaddr= (struct kens_sockaddr_in *) malloc(sizeof(struct kens_sockaddr_in));

    if (new_sock_info->my_sockaddr == NULL || new_sock_info->peer_sockaddr == NULL) {
      if (new_sock_info->my_sockaddr != NULL) { free(new_sock_info->my_sockaddr); }
      if (new_sock_info->peer_sockaddr != NULL) { free(new_sock_info->peer_sockaddr); }
      free(new_sock_info);
      return;
    }

    sock_info->current_backlog++;
    cloneSockInfo(new_sock_info, sock_info);
    printf("SYN received!!!!!!!!!!!\n");

    new_sock_info->peer_sockaddr->sin_addr = income_src_ip;
    new_sock_info->peer_sockaddr->sin_port = income_src_port;

    // FIXTME: 아래 2개 수정할 필요 있음
    new_sock_info->peer_sockaddr->sin_len = new_sock_info->my_sockaddr->sin_len;
    new_sock_info->peer_sockaddr->sin_family = AF_INET;

    sock_table.push_back(new_sock_info);
    sock_info->child_sock_list->push_back(new_sock_info);

    sendPacket("IPv4", std::move(response_packet));
  }
  // printf("syn err 2\n");
  return;
}

void TCPAssignment::handleAckPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  Packet packet_to_client = packet->clone();
  struct sock_info* sock_info;
  sock_info_itr itr;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    sock_info = *itr;
    if (sock_info->my_sockaddr != NULL
        && (sock_info->my_sockaddr->sin_port == 0 || sock_info->my_sockaddr->sin_port == income_dst_port)
        && (sock_info->my_sockaddr->sin_addr == 0 || sock_info->my_sockaddr->sin_addr == income_dst_ip)) {
      if (sock_info->status == Status::SYN_RCVD) {
        break;
      }
    }
  }
  if (itr == sock_table.end()) {
    // printf("NO ESTAB\n");
    return;
  }
  sock_info->status = Status::ESTAB;
  printf("ESTAB!!!!!!!!!!!\n");
  sock_info->parent_sock->current_backlog--;

  setPacketSrcDst(&packet_to_client, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
  sendPacket("IPv4", std::move(packet_to_client));
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // printf("packet arrived\n");
  if (isSynAckPacket(&packet)) {
    return handleSynAckPacket(fromModule, &packet);
  } else if (isSynPacket(&packet)) {
    return handleSynPacket(fromModule, &packet);
  } else if (isAckPacket(&packet)) {
    return handleAckPacket(fromModule, &packet);
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  TimerPayload *timerPayload = std::any_cast<TimerPayload*>(payload);
  switch (timerPayload->timerType)
  {
  case TimerType::ACCEPT: {
    // TODO: 버그 가능성 없는지 확인. 단순히 리스트 앞을 제거해서 A 타이머가 작동하고 B 타이머를 삭제할 수가 있음.
    UUID waiterId = accept_wait_timers.front();
    cancelTimer(waiterId);
    accept_wait_timers.erase(accept_wait_timers.begin());
    acceptHandler(timerPayload->syscallUUID, timerPayload->pid, timerPayload->param);
    free(timerPayload);
  }
  default:
    break;
  }
}

} // namespace E

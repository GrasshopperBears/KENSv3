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

// ------------------enums start------------------
enum Status {
  CLOSED,
  LISTEN,
  SYN_RCVD,
  SYN_SENT,
  ESTAB
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
  std::list<sock_info*>* backlog_list;
  enum Status status;
  int backlog;
};

struct kens_sockaddr_in {
  __uint8_t sin_len;
  sa_family_t sin_family;
  in_port_t sin_port;
  uint32_t sin_addr;
};

struct AcceptQueueItem {
  UUID syscallUUID;
  int pid;
  SystemCallInterface::SystemCallParameter *param;
};

struct ConnectListItem {
  UUID syscallUUID;
  int pid;
  int fd;
};
// ----------------structs end----------------

const int PACKET_OFFSET = 14;
const int SEGMENT_OFFSET = PACKET_OFFSET + 20;
int SEQNUM = 100;

std::list<sock_info*> sock_table;

// accept_queue is a queue for blocking accept.
// pushed by acceptHandler and poped by handleAckPacket.
std::list<AcceptQueueItem *> accept_queue;
std::list<ConnectListItem *> connect_list;
using sock_info_itr = typename std::list<struct sock_info*>::iterator;
using accept_queue_itr = typename std::list<struct AcceptQueueItem*>::iterator;
using connect_list_itr = typename std::list<struct ConnectListItem*>::iterator;

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {
  // cleanup global list
  if (sock_table.size() > 0) {
    sock_info_itr sock_info_itr = sock_table.begin();
    while (sock_info_itr != sock_table.end()) {
      sock_info_itr = sock_table.erase(sock_info_itr);
    }
  }
  if (accept_queue.size() > 0) {
    accept_queue_itr accept_queue_itr = accept_queue.begin();
    while (accept_queue_itr != accept_queue.end()) {
      accept_queue_itr = accept_queue.erase(accept_queue_itr);
    }
  }
  if (connect_list.size() > 0) {
    connect_list_itr connect_list_itr = connect_list.begin();
    while (connect_list_itr != connect_list.end()) {
      connect_list_itr = connect_list.erase(connect_list_itr);
    }
  }
}

sock_info_itr find_sock_info(int pid, int fd) {
  sock_info_itr itr;
  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    if ((*itr)->pid == pid && (*itr)->fd == fd) { break; }
  }
  return itr;
}

void TCPAssignment::acceptHandler(UUID syscallUUID, int pid,
                                  SystemCallParameter *param) {
  int fd = std::get<int>(param->params[0]);
  struct sockaddr_in* param_addr = (struct sockaddr_in *) static_cast<struct sockaddr *>(std::get<void *>(param->params[1]));
  socklen_t* addrlen = static_cast<socklen_t *>(std::get<void *>(param->params[2]));

  struct sock_info *sock_info, *parent_sock_info;
  sock_info_itr itr;
  struct AcceptQueueItem *accept_queue_item;

  // First, find appropriate parent socket
  itr = find_sock_info(pid, fd);
  if (itr == sock_table.end()) {
    free(param);
    return returnSystemCall(syscallUUID, -1);
  }
  parent_sock_info = *itr;

  if (parent_sock_info->child_sock_list->size() > 0) {
    for (itr = parent_sock_info->child_sock_list->begin(); itr != parent_sock_info->child_sock_list->end(); ++itr) {
      sock_info = *itr;
      // Socket that established but not returned yet;
      if (sock_info->status == Status::ESTAB && sock_info->fd < 0) {
        sock_info->fd = createFileDescriptor(sock_info->pid);

        param_addr->sin_addr.s_addr = sock_info->peer_sockaddr->sin_addr;
        param_addr->sin_family = sock_info->peer_sockaddr->sin_family;
        param_addr->sin_port = sock_info->peer_sockaddr->sin_port;

        *addrlen = sizeof(struct sockaddr_in);

        free(param);
        return returnSystemCall(syscallUUID, sock_info->fd);
      }
    }
  }

  // When this code is executed, we have to wait util socket to be established
  // or next packet comes from client
  accept_queue_item = (struct AcceptQueueItem *) malloc(sizeof(struct AcceptQueueItem));
  accept_queue_item->syscallUUID = syscallUUID;
  accept_queue_item->pid = pid;
  accept_queue_item->param = param;

  accept_queue.push_back(accept_queue_item);
  return;
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
    sock_info->backlog_list = new std::list<struct sock_info*>();
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
  case CONNECT: {
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    printf("CONNECT\n");
    int fd = std::get<int>(param.params[0]);
    sock_info_itr sock_info_itr = find_sock_info(pid, fd);
    if (sock_info_itr == sock_table.end()) {
      returnSystemCall(syscallUUID, -1);
      break;
    }
    struct sock_info* sock_info = *sock_info_itr;
    struct sockaddr_in* param_addr =
      (struct sockaddr_in *) static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    ipv4_t dstIp = {
      (u_int8_t) (param_addr->sin_addr.s_addr),
      (u_int8_t) (param_addr->sin_addr.s_addr >> 8),
      (u_int8_t) (param_addr->sin_addr.s_addr >> 16),
      (u_int8_t) (param_addr->sin_addr.s_addr >> 24)
    };

    // TODO: 포트 및 routingTable 관리
    uint16_t port = htons(9998);
    ipv4_t _ip = getIPAddr((uint16_t) getRoutingTable(dstIp)).value();
    
    setRoutingTable(_ip, 0, ntohs(port));

    u_int32_t myIp = (_ip[0]) + (_ip[1] << 8) + (_ip[2] << 16) + (_ip[3] << 24);
    Packet synPkt (54);
    setPacketSrcDst(&synPkt, &myIp, &port, &param_addr->sin_addr.s_addr, &param_addr->sin_port);
    
    struct kens_sockaddr_in* addr = (struct kens_sockaddr_in *) malloc(sizeof(struct kens_sockaddr_in));
    addr->sin_len = sizeof(addr->sin_addr);
    addr->sin_family = AF_INET;
    addr->sin_port = port;
    addr->sin_addr = myIp;
    sock_info->my_sockaddr = addr;

    uint8_t tcp_len = 5 << 4;
    uint flag = 2;
    uint16_t window_size = htons(0xc800);
    uint32_t nSEQNUM = htonl(SEQNUM);
    
    synPkt.writeData(SEGMENT_OFFSET + 4, &nSEQNUM, 4);
    synPkt.writeData(SEGMENT_OFFSET + 12, &tcp_len, 1);
    synPkt.writeData(SEGMENT_OFFSET + 13, &flag, 1);
    synPkt.writeData(SEGMENT_OFFSET + 14, &window_size, 2);

    // checksum
    char buffer[20];
    synPkt.readData(SEGMENT_OFFSET, buffer, 20);
    uint16_t checksum = NetworkUtil::tcp_sum(myIp, param_addr->sin_addr.s_addr, (uint8_t *)buffer, 20);
    checksum = ~checksum;
    checksum = htons(checksum);
    synPkt.writeData(SEGMENT_OFFSET + 16, &checksum, 2);

    sendPacket("IPv4", std::move(synPkt));
    sock_info->status = SYN_SENT;

    struct ConnectListItem* connect_list_item = (struct ConnectListItem *) malloc(sizeof(struct ConnectListItem));
    connect_list_item->fd = fd;
    connect_list_item->pid = pid;
    connect_list_item->syscallUUID = syscallUUID;
    connect_list.push_back(connect_list_item);
    break;
  }
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
  case GETPEERNAME: {
    // this->syscall_getpeername(
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
    struct kens_sockaddr_in* peerAddr_in = (*found_item_itr)->peer_sockaddr;

    addr->sin_addr.s_addr = peerAddr_in->sin_addr;
    addr->sin_family = peerAddr_in->sin_family;
    addr->sin_port = peerAddr_in->sin_port;
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
    
    *addrlen = peerAddr_in->sin_len;
    returnSystemCall(syscallUUID, 0);

    break;
  }
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

void TCPAssignment::setPacketSrcDst(Packet *packet, uint32_t *src_ip, uint16_t *src_port, uint32_t *dst_ip, uint16_t *dst_port) {
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
  dst->backlog_list = NULL;
  dst->child_sock_list = NULL;
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
        && sock_info->my_sockaddr->sin_port == income_dst_port
        && (sock_info->my_sockaddr->sin_addr == 0 || sock_info->my_sockaddr->sin_addr == income_dst_ip))
    {
      break;
    }
  }

  if (itr == sock_table.end()) {
    return;
  }

  // Server: initiallize TCP connection (1st step of 3-way handshake)
  if (sock_info->status == Status::LISTEN) {
    Packet response_packet = packet->clone();   // TODO: more than clone
    struct sock_info* new_sock_info;

    setPacketSrcDst(&response_packet, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
    
    // backlog count check
    if (sock_info->backlog <= sock_info->backlog_list->size()) {
      // 무시 혹은 RST flag set
      // TODO: (maybe) clone한 패킷 처리?
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

    cloneSockInfo(new_sock_info, sock_info);

    new_sock_info->peer_sockaddr->sin_addr = income_src_ip;
    new_sock_info->peer_sockaddr->sin_port = income_src_port;
    new_sock_info->peer_sockaddr->sin_len = sizeof(struct sockaddr_in);
    // TODO: family도 packet 통해서 정보를 얻어야 하나?
    new_sock_info->peer_sockaddr->sin_family = AF_INET;

    sock_table.push_back(new_sock_info);
    sock_info->backlog_list->push_back(new_sock_info);

    sendPacket("IPv4", std::move(response_packet));
  }

  return;
}

void TCPAssignment::handleAckPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  Packet packet_to_client = packet->clone();
  struct sock_info *sock_info, *parent_sock_info;
  struct AcceptQueueItem *accept_queue_item;
  sock_info_itr itr;
  accept_queue_itr accept_queue_itr;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  // First find parent socket by income_dst_ip and income_dst_port
  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    parent_sock_info = *itr;
    if (parent_sock_info->my_sockaddr != NULL
        && (parent_sock_info->my_sockaddr->sin_addr == 0 || parent_sock_info->my_sockaddr->sin_addr == income_dst_ip)
        && parent_sock_info->my_sockaddr->sin_port == income_dst_port)
    {
      break;
    }
  }

  if (itr == sock_table.end()) { return; }

  if (parent_sock_info->status == Status::LISTEN) {
    if (parent_sock_info->backlog_list->size() == 0) { return; }

    // Filter by client IP and port
    for (itr = parent_sock_info->backlog_list->begin(); itr != parent_sock_info->backlog_list->end(); ++itr) {
      sock_info = *itr;
      if (sock_info->peer_sockaddr->sin_addr == income_src_ip && sock_info->peer_sockaddr->sin_port == income_src_port) {
        break;
      }
    }
    if (itr == parent_sock_info->backlog_list->end()) { return; }
    
    parent_sock_info->backlog_list->erase(itr);

    sock_info->status = Status::ESTAB;
    parent_sock_info->child_sock_list->push_back(sock_info);

    if (accept_queue.size() > 0) {
      for (accept_queue_itr = accept_queue.begin(); accept_queue_itr != accept_queue.end(); ++itr) {
        accept_queue_item = *accept_queue_itr;
        if (parent_sock_info->pid == accept_queue_item->pid && parent_sock_info->fd == std::get<int>(accept_queue_item->param->params[0])) {
          accept_queue.erase(accept_queue_itr);
          acceptHandler(accept_queue_item->syscallUUID, accept_queue_item->pid, accept_queue_item->param);
          free(accept_queue_item);
          return;
        }
      }
    }
    setPacketSrcDst(&packet_to_client, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
    sendPacket("IPv4", std::move(packet_to_client));
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // printf("PacketArrived\n");
  if (isSynAckPacket(&packet)) {
    return handleSynAckPacket(fromModule, &packet);
  } else if (isSynPacket(&packet)) {
    return handleSynPacket(fromModule, &packet);
  } else if (isAckPacket(&packet)) {
    return handleAckPacket(fromModule, &packet);
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  printf("TimerCallback\n");
}

} // namespace E

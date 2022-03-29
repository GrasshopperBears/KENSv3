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

const int PACKET_OFFSET = 14;
const int SEGMENT_OFFSET = PACKET_OFFSET + 20;

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

struct TimerPayload {
  UUID syscallUUID;
  int pid;
  const SystemCallInterface::SystemCallParameter *param;
  TimerType timerType;
};

struct sock_table_item {
  int pid;
  int fd;
  struct kens_sockaddr_in* my_sockaddr;
  struct kens_sockaddr_in* peer_sockaddr;
  enum Status status;
  int backlog;
  std::vector<sock_table_item*> backlog_list;
  UUID syscallUUID;
};

std::vector<sock_table_item*> sock_table;
std::vector<UUID> accept_wait_timers;
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

void TCPAssignment::acceptHandler(UUID syscallUUID, int pid, const SystemCallInterface::SystemCallParameter *param) {
  printf("accept\n");

  sock_table_item_itr itr;

  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    if ((*itr)->status == E::ESTAB) {
      break;
    }
  }
  if (itr == sock_table.end()) {
    struct TimerPayload payload;
    payload.syscallUUID = syscallUUID;
    payload.pid = pid;
    payload.param = param;
    payload.timerType = E::ACCEPT;

    UUID timerId = addTimer(payload, 2000);
    accept_wait_timers.push_back(timerId);
    return;
  }
  
  struct sock_table_item* found_sock_table_item = *itr;
  struct sockaddr_in *param_addr = 
      (struct sockaddr_in *)(static_cast<struct sockaddr *>(std::get<void *>(param->params[1])));
  
  param_addr->sin_addr.s_addr = found_sock_table_item->peer_sockaddr->sin_addr;
  param_addr->sin_family = found_sock_table_item->peer_sockaddr->sin_family;
  param_addr->sin_port = found_sock_table_item->peer_sockaddr->sin_port;

  returnSystemCall(syscallUUID, found_sock_table_item->fd);
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;

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

    sock_table_item->my_sockaddr = NULL;
    sock_table_item->peer_sockaddr = NULL;
    sock_table_item->fd = fd;
    sock_table_item->pid = pid;
    sock_table_item->status = CLOSED;
    sock_table_item->backlog_list = {};
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

    if (sock_table_item->my_sockaddr != NULL)
      free(sock_table_item->my_sockaddr);
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
  case LISTEN: {
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    fd = std::get<int>(param.params[0]);
    int backlog = std::get<int>(param.params[1]);
    printf("listen, backlog=%d\n", backlog);
    
    sock_table_item_itr sock_table_item_itr = find_sock_alloc_item(pid, fd);
    struct sock_table_item* sock_table_item = *sock_table_item_itr;

    if (sock_table_item_itr == sock_table.end() || sock_table_item->status == E::LISTEN) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    if (backlog < 0) {
      sock_table_item->backlog = 0;
    } else if (backlog > SOMAXCONN) {
      sock_table_item->backlog = SOMAXCONN;
    } else {
      sock_table_item->backlog = backlog;
    }
    sock_table_item->status = E::LISTEN;
    sock_table_item->syscallUUID = syscallUUID;
    returnSystemCall(syscallUUID, 0);

    break;
  }
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));

    acceptHandler(syscallUUID, pid, &param);
    break;
  case BIND: {
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    printf("bind\n");
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
      if ((*itr)->my_sockaddr != NULL && (
        (*itr)->my_sockaddr->sin_addr == param_addr->sin_addr.s_addr || 
        param_addr->sin_addr.s_addr == NL_INADDR_ANY ||
        (*itr)->my_sockaddr->sin_addr == NL_INADDR_ANY)
      ) {
        if ((*itr)->my_sockaddr->sin_port == param_addr->sin_port) {
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
    if (sock_table_item->my_sockaddr != NULL) {
      returnSystemCall(syscallUUID, -1);
    }

    struct kens_sockaddr_in* my_addr = (struct kens_sockaddr_in *) malloc(sizeof(struct kens_sockaddr_in));

    // TODO: free peer_addr
    struct kens_sockaddr_in* peer_addr = (struct kens_sockaddr_in *) malloc(sizeof(struct kens_sockaddr_in));
    if (sock_table_item == NULL) {
      printf("Error: can't allocate memory(sockaddr_in)\n");
      returnSystemCall(syscallUUID, -1);
    }

    my_addr->sin_len = sizeof(param_addr->sin_addr);
    my_addr->sin_family = param_addr->sin_family;
    my_addr->sin_port = param_addr->sin_port;
    my_addr->sin_addr = param_addr->sin_addr.s_addr;
    sock_table_item->my_sockaddr = my_addr;
    sock_table_item->peer_sockaddr = peer_addr;

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

bool isSYNPacket(Packet *packet) {
  uint8_t syn = 0;
  packet->readData(SEGMENT_OFFSET + 13, &syn, 1);
  return (syn >> 1) & 1;
}

bool isSYNACKPacket(Packet *packet) {
  uint8_t syn = 0;
  packet->readData(SEGMENT_OFFSET + 13, &syn, 1);
  return ((syn >> 1) & 1) & ((syn >> 4) & 1);
}

bool isACKPacket(Packet *packet) {
  uint8_t syn = 0;
  packet->readData(SEGMENT_OFFSET + 13, &syn, 1);
  return (syn >> 4) & 1;
}

enum SegmentFlag {
  FIN = 0,
  SYN = 1,
  RST = 2,
  PSH = 3,
  ACK = 4,
  URG = 5,
  ECE = 6,
  CWR = 7
};

// Segment flag는 KENS에서 설정하는 것으로 보임
void setSegmentFlag(Packet *packet, SegmentFlag flag) {
  uint8_t syn = 0;
  packet->readData(SEGMENT_OFFSET + 13, &syn, 1);
  syn |= (1UL << flag);
  packet->writeData(SEGMENT_OFFSET + 13, &syn, 1);
}

uint32_t getSeqNumber(Packet *packet) {
  uint32_t seqNumber = 0;
  packet->readData(SEGMENT_OFFSET + 4, &seqNumber, 4);
  return ntohl(seqNumber);
}

void setSeqNumber(Packet *packet, uint32_t *seqNumber) {
  *seqNumber = htonl(*seqNumber);
  packet->writeData(SEGMENT_OFFSET + 4, seqNumber, 4);
}

uint32_t getAckNumber(Packet *packet) {
  uint32_t ackNumber = 0;
  packet->readData(SEGMENT_OFFSET + 8, &ackNumber, 4);
  return ntohl(ackNumber);
}

void setAckNumber(Packet *packet, uint32_t *ackNumber) {
  *ackNumber = htonl(*ackNumber);
  packet->writeData(SEGMENT_OFFSET + 8, ackNumber, 4);
}

void TCPAssignment::handleACKPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  Packet packet_to_client = packet->clone();

  sock_table_item_itr itr;
  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    if ((*itr)->my_sockaddr->sin_addr == 0 || (*itr)->my_sockaddr->sin_addr == income_dst_ip) {
      if ((*itr)->status == SYN_RCVD) {
        break;
      }
    }
  }
  if (itr == sock_table.end()) {
    // setSegmentFlag(&packet_to_client, E::RST);
    // sendPacket("IPv4", packet_to_client);
    return;
  }
  struct sock_table_item* found_sock_table_item = *itr;
  found_sock_table_item->status = E::ESTAB;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);
  setPacketSrcDst(&packet_to_client, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
  sendPacket("IPv4", packet_to_client);
}

void TCPAssignment::handleSYNACKPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  Packet packet_to_client = packet->clone();

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);
  setPacketSrcDst(&packet_to_client, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
  sendPacket("IPv4", packet_to_client);
}

void TCPAssignment::handleSYNPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  // address 확인 방법
  // struct in_addr addr;
  // addr.s_addr = income_dst_ip;
  // printf("dst: %s\n", inet_ntoa(addr));
  
  sock_table_item_itr itr;
  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    if ((*itr)->my_sockaddr->sin_addr == 0 || (*itr)->my_sockaddr->sin_addr == income_dst_ip) {
      break;
    }
  }
  struct sock_table_item* found_sock_table_item = *itr;

  uint8_t flags;
  
  if (found_sock_table_item->status == E::LISTEN) {
    size_t packet_size = 54;
    Packet packet_to_client = packet->clone();

    setPacketSrcDst(&packet_to_client, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
    if (found_sock_table_item->backlog <= found_sock_table_item->backlog_list.size()) {
      printf("overflow\n");
      setSegmentFlag(&packet_to_client, E::RST);
      sendPacket("IPv4", packet_to_client);
      return;
    }
    struct sock_table_item* new_sock_table_item = (struct sock_table_item*) malloc(sizeof(struct sock_table_item));

    memcpy(new_sock_table_item, found_sock_table_item, sizeof(struct sock_table_item));
    new_sock_table_item->fd = createFileDescriptor(new_sock_table_item->pid);
    new_sock_table_item->status = E::SYN_RCVD;
    sock_table.push_back(new_sock_table_item);
    found_sock_table_item->backlog_list.push_back(new_sock_table_item);


    new_sock_table_item->peer_sockaddr->sin_addr = income_src_ip;
    new_sock_table_item->peer_sockaddr->sin_port = income_src_port;
    // FIXTME: 아래 2개 수정할 필요 있음
    new_sock_table_item->peer_sockaddr->sin_len = new_sock_table_item->my_sockaddr->sin_len;
    new_sock_table_item->peer_sockaddr->sin_family = AF_INET;

    // uint32_t syn = getSeqNumber(packet);
    // uint32_t ack = 1234;
    // printf("syn: %x\n", syn);
    // syn++;
    // setSeqNumber(&packet_to_client, &ack);
    // setAckNumber(&packet_to_client, &syn);
    // setSegmentFlag(&packet_to_client, E::SYN);
    // setSegmentFlag(&packet_to_client, E::ACK);

    // packet_to_client.readData(SEGMENT_OFFSET+13, &flags, 1);
    // printf("flags: %d\n", flags);


    // set ttl
    // uint16_t ttl = 64;
    // packet_to_client.writeData(PACKET_OFFSET+8, &ttl, 1);

    // set ihl and version
    // uint8_t version_ihl = 0;
    // version_ihl |= (4 << 4);
    // version_ihl |= 5;
    // packet_to_client.writeData(PACKET_OFFSET, &version_ihl, 1);

    // set total len
    // uint16_t total_len = htons(20+20);
    // packet_to_client.writeData(PACKET_OFFSET+2, &total_len, 2);

    // set protocol
    // uint8_t protocol = 8;
    // packet_to_client.writeData(PACKET_OFFSET+9, &protocol, 1);

    // set header and total length
    // uint8_t header_size = 20;
    // uint16_t total_length = htons(40);
    // header_size |= (1 << 6);
    // packet_to_client.writeData(PACKET_OFFSET, &header_size, 1);
    // packet_to_client.writeData(PACKET_OFFSET + 2, &total_length, 2);

    // set TCP header length
    // uint8_t segment_length = 5;
    // packet_to_client.writeData(SEGMENT_OFFSET + 12, &segment_length, 1);

    // set checksum
    // uint8_t ip_header_buffer[20];
    // packet_to_client.readData(PACKET_OFFSET, ip_header_buffer, 20);
    // uint16_t checksum = NetworkUtil::one_sum(ip_header_buffer, 20);
    // checksum = ~checksum;
    // checksum = htons(checksum);
    // packet_to_client.writeData(PACKET_OFFSET + 10, (uint8_t *)&checksum, 2);

    sendPacket("IPv4", std::move(packet_to_client));
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;

  if (isSYNACKPacket(&packet)) {
    printf("synack arrived\n");
    return handleSYNACKPacket(fromModule, &packet);
  } else if (isSYNPacket(&packet)) {
    printf("syn packet~\n");
    return handleSYNPacket(fromModule, &packet);
  } else if (isACKPacket(&packet)) {
    printf("ack arrived\n");
    return handleACKPacket(fromModule, &packet);
  } else {
    printf("another packet\n");
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  TimerPayload timerPayload = std::any_cast<TimerPayload>(payload);
  switch (timerPayload.timerType)
  {
  case E::ACCEPT: {
    UUID waiterId = accept_wait_timers.front();
    cancelTimer(waiterId);
    accept_wait_timers.erase(accept_wait_timers.begin());
    return acceptHandler(timerPayload.syscallUUID, timerPayload.pid, timerPayload.param);
  }
  default:
    break;
  }
}

} // namespace E

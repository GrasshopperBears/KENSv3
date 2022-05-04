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

enum BufferStatus {
  NORMAL,
  WAITING,
  BUFFERFILLED
};
// ------------------enums end------------------
const int PACKET_OFFSET = 14;
const int SEGMENT_OFFSET = PACKET_OFFSET + 20;
const int DATA_OFFSET = SEGMENT_OFFSET + 20;
const int BUFFER_SIZE = 2048;
const int MSS = 1500;
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
  UUID connect_syscallUUID;
  struct RecvSpace* recvSpace;
  struct SendSpace* sendSpace;
  uint32_t my_seq_base;
  uint32_t peer_seq_base;
};

struct kens_sockaddr_in {
  __uint8_t sin_len;
  sa_family_t sin_family;
  in_port_t sin_port;
  uint32_t sin_addr;
};

struct SyscallQueueItem {
  UUID syscallUUID;
  int pid;
  SystemCallInterface::SystemCallParameter *param;
  int fd;
  char* write_buffer;
  int writeLen;
};

struct UsingResourceInfo {
  uint32_t sin_addr;
  in_port_t port;
  int fd;
  int pid;
  UUID syscalUUID;
};

struct RecvSpace {
  char buffer[BUFFER_SIZE];
  enum BufferStatus bufferStatus;
  void *waitBuffer;
  UUID waitUUID;
  int waitLen;
  int restSpace;
  uint32_t expect_seq;
  uint32_t recv_base;
  Packet *recv_pkt;
};

struct PacketNode {
  Packet* packet;
  char* buffer_ptr;
  size_t buffer_size;
  uint32_t seq_num;
};

struct SendSpace {
  char buffer[BUFFER_SIZE];
  char* next_write;

  // TODO: clear on close
  std::list<PacketNode*>* sent_packet_list;
  std::list<SyscallQueueItem*>* waiting_write_list;

  // enum BufferStatus bufferStatus = NORMAL;
};
// ----------------structs end----------------

std::list<sock_info*> sock_table;

// accept_queue is a queue for blocking accept.
// pushed by acceptHandler and poped by handleAckPacket.
std::list<SyscallQueueItem *> accept_queue;

// using_resource_list is a list for checking duplicate info.
std::list<UsingResourceInfo *> using_resource_list;

using sock_info_itr = typename std::list<struct sock_info*>::iterator;
using syscall_queue_itr = typename std::list<struct SyscallQueueItem*>::iterator;
using using_resource_itr = typename std::list<struct UsingResourceInfo*>::iterator;
using packet_node_itr = typename std::list<struct PacketNode*>::iterator;

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
    syscall_queue_itr accept_queue_itr = accept_queue.begin();
    SyscallQueueItem *tmp;
    while (accept_queue_itr != accept_queue.end()) {
      tmp = *accept_queue_itr;
      accept_queue_itr = accept_queue.erase(accept_queue_itr);
      free(tmp->param);
      free(tmp);
    }
  }
  if (using_resource_list.size() > 0) {
    using_resource_itr using_resource_itr = using_resource_list.begin();
    UsingResourceInfo *tmp;
    while (using_resource_itr != using_resource_list.end()) {
      tmp = *using_resource_itr;
      using_resource_itr = using_resource_list.erase(using_resource_itr);
      free(tmp);
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

void set_packet_checksum(Packet *packet, uint32_t src_ip, uint32_t dst_ip) {
  uint64_t packet_length = packet->getSize() - SEGMENT_OFFSET;
  uint16_t zero = 0;
  int checksum_pos = 16, checksum_size = 2;
  char buffer[packet_length];

  // Init checksum field
  packet->writeData(SEGMENT_OFFSET + checksum_pos, &zero, checksum_size);

  packet->readData(SEGMENT_OFFSET, buffer, packet_length);
  uint16_t checksum = NetworkUtil::tcp_sum(src_ip, dst_ip, (uint8_t *)buffer, packet_length);
  checksum = ~checksum;
  checksum = htons(checksum);
  packet->writeData(SEGMENT_OFFSET + checksum_pos, &checksum, checksum_size);
}

void set_packet_flags(Packet *packet, uint8_t flags) {
  packet->writeData(SEGMENT_OFFSET + 13, &flags, 1);
}

void set_packet_length(Packet *packet, uint8_t len = 20) {
  uint8_t len_converted = (len / 4) << 4;
  packet->writeData(SEGMENT_OFFSET + 12, &len_converted, 1);
}

u_int32_t getRandomSequnceNumber() {
  u_int32_t seq_num;
  srand((unsigned int) time(NULL));
  seq_num = (uint32_t) (rand() + rand()); // MAX of rand() is 0x7fffffff
  return seq_num;
}

uint32_t get_seq_number(Packet *pkt) {
  uint32_t seq;
  pkt->readData(SEGMENT_OFFSET + 4, &seq, 4);
  return ntohl(seq);
}

uint32_t get_ack_number(Packet *pkt) {
  uint32_t ack;
  pkt->readData(SEGMENT_OFFSET + 8, &ack, 4);
  return ntohl(ack);
}

void set_seq_number(Packet *pkt, uint32_t seq) {
  uint32_t seq_converted = htonl(seq);
  pkt->writeData(SEGMENT_OFFSET + 4, &seq_converted, 4);
}

void set_ack_number(Packet *pkt, uint32_t ack) {
  uint32_t ack_converted = htonl(ack);
  pkt->writeData(SEGMENT_OFFSET + 8, &ack_converted, 4);
}

/*
  set_handshake_seqack_number: Set seq and ack number of res_pkt.
  Parameter "flag":
    TH_ACK | TH_SYN: [server] ---SYNACK---> [client]
    TH_ACK         : [client] ------ACK---> [server] 
*/
void set_handshake_seqack_number(Packet *req_pkt, Packet *res_pkt, uint flag) {
  uint32_t req_seq = get_seq_number(req_pkt);
  uint32_t req_ack = get_ack_number(req_pkt);
  uint32_t new_seq, new_ack = req_seq + 1;

  if (flag == (TH_ACK | TH_SYN)) {
    new_seq = getRandomSequnceNumber();
  }
  else if (flag == TH_ACK) {
    new_seq = req_ack;
  }
  else {
    printf("Invalid flag: %x\n", flag);
    return;
  }
  set_seq_number(res_pkt, new_seq);
  set_ack_number(res_pkt, new_ack);
}

struct kens_sockaddr_in* get_new_sockaddr_in(uint32_t ip, uint16_t port) {
  struct kens_sockaddr_in* addr = (struct kens_sockaddr_in *) malloc(sizeof(struct kens_sockaddr_in));
  if (addr == NULL) return NULL;

  addr->sin_len = sizeof(addr->sin_addr);
  addr->sin_family = AF_INET;
  addr->sin_port = port;
  addr->sin_addr = ip;
  return addr;
}

void TCPAssignment::acceptHandler(UUID syscallUUID, int pid,
                                  SystemCallParameter *param) {
  int fd = std::get<int>(param->params[0]);
  struct sockaddr_in* param_addr = (struct sockaddr_in *) static_cast<struct sockaddr *>(std::get<void *>(param->params[1]));
  socklen_t* addrlen = static_cast<socklen_t *>(std::get<void *>(param->params[2]));

  struct sock_info *sock_info, *parent_sock_info;
  sock_info_itr itr;
  struct SyscallQueueItem *accept_queue_item;

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
  accept_queue_item = (struct SyscallQueueItem *) malloc(sizeof(struct SyscallQueueItem));
  if (accept_queue_item == NULL) {
    return returnSystemCall(syscallUUID, -1);
  }
  accept_queue_item->syscallUUID = syscallUUID;
  accept_queue_item->pid = pid;
  accept_queue_item->param = param;

  accept_queue.push_back(accept_queue_item);
  return;
}

void TCPAssignment::writeHandler(UUID syscallUUID, int pid, SyscallQueueItem *writeQueueItem) {
  // printf("write handler\n");
  int fd = writeQueueItem->fd;
  char* write_buffer = writeQueueItem->write_buffer;
  int writeLen = writeQueueItem->writeLen;
  int buffer_ptr_cnt = 0;
  sock_info_itr sock_info_itr = find_sock_info(pid, fd);
  struct sock_info* sock_info = *sock_info_itr;
  char *buffer_ptr, *current_buffer_begin;

  if (sock_info_itr == sock_table.end() || sock_info->status != Status::ESTAB) {
    free(write_buffer);
    return returnSystemCall(syscallUUID, -1);
  }

  struct SendSpace* sendSpace = sock_info->sendSpace;
  buffer_ptr = sendSpace->next_write;

  while (buffer_ptr[0] == 0 && buffer_ptr_cnt < writeLen) {
    buffer_ptr++;
    buffer_ptr_cnt++;
    if (buffer_ptr >= sendSpace->buffer + BUFFER_SIZE) { buffer_ptr -= BUFFER_SIZE; }
  }

  if (buffer_ptr_cnt < writeLen) {
    // block. buffer is full.
    sock_info->sendSpace->waiting_write_list->push_back(writeQueueItem);
    // printf("blocked\n");
    return;
  }

  if (buffer_ptr >= sendSpace->buffer) {
    memset(sendSpace->next_write, 0, writeLen);
    memcpy(sendSpace->next_write, write_buffer, writeLen);
  } else {
    size_t first = sendSpace->buffer + BUFFER_SIZE - sendSpace->next_write;
    size_t second = buffer_ptr - sendSpace->buffer;
    memset(sendSpace->next_write, 0, first);
    memset(sendSpace->buffer, 0, second);
    memcpy(sendSpace->next_write, write_buffer, first);
    memcpy(sendSpace->buffer, write_buffer + first, second);
  }

  current_buffer_begin = sendSpace->next_write;
  sendSpace->next_write = buffer_ptr;

  if (sendSpace->next_write >= sendSpace->buffer + BUFFER_SIZE) {
    sendSpace->next_write -= BUFFER_SIZE;
  }
  free(writeQueueItem->write_buffer);
  free(writeQueueItem);

  uint64_t packet_count = writeLen / MSS;
  if (writeLen % MSS != 0) { packet_count++; }

  for (int i = 0; i < packet_count; i++) {
    uint64_t packet_size = MSS, buffer_offset = MSS * i;
    if (writeLen - buffer_offset < MSS) { packet_size = writeLen - buffer_offset; }

    Packet senderPacket(DATA_OFFSET + packet_size);
    setPacketSrcDst(&senderPacket, &sock_info->my_sockaddr->sin_addr, &sock_info->my_sockaddr->sin_port,
      &sock_info->peer_sockaddr->sin_addr, &sock_info->peer_sockaddr->sin_port);

    set_seq_number(&senderPacket, sock_info->my_seq_base + buffer_offset);
    set_ack_number(&senderPacket, sock_info->peer_seq_base);
    set_packet_flags(&senderPacket, TH_ACK);
    set_packet_length(&senderPacket);

    senderPacket.writeData(DATA_OFFSET, current_buffer_begin + buffer_offset, packet_size);
    set_packet_checksum(&senderPacket, sock_info->my_sockaddr->sin_addr, sock_info->peer_sockaddr->sin_addr);

    PacketNode *packetNode = (PacketNode *) malloc(sizeof(struct PacketNode));
    packetNode->packet = &senderPacket;
    packetNode->buffer_ptr = current_buffer_begin + buffer_offset;
    packetNode->buffer_size = packet_size;
    packetNode->seq_num = sock_info->my_seq_base + buffer_offset;

    sock_info->sendSpace->sent_packet_list->push_back(packetNode);
    sock_info->my_seq_base += writeLen;

    sendPacket("IPv4", std::move(senderPacket));
  }
  returnSystemCall(syscallUUID, writeLen);
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
    sock_info->recvSpace = NULL;
    sock_info->sendSpace = NULL;
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
    if (sock_info->recvSpace != NULL && sock_info->recvSpace->recv_pkt != NULL)
      free(sock_info->recvSpace->recv_pkt);
    if (sock_info->recvSpace != NULL)
      free(sock_info->recvSpace);
    
    // TODO: cleanup sendSpace
    if (sock_info->sendSpace != NULL)
      free(sock_info->sendSpace);
    free(sock_info);

    struct UsingResourceInfo* using_resource_info;
    using_resource_itr using_resource_itr;
    for (using_resource_itr = using_resource_list.begin(); using_resource_itr != using_resource_list.end(); using_resource_itr++) {
      if ((*using_resource_itr)->fd == fd && (*using_resource_itr)->pid == pid) {
        using_resource_info = *using_resource_itr;
        using_resource_list.erase(using_resource_itr);
        free(using_resource_info);
        break;
      }
    }
    delete sock_info->backlog_list;
    delete sock_info->child_sock_list;

    returnSystemCall(syscallUUID, 0);
    break;
  }
  case READ: {
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    int fd = std::get<int>(param.params[0]);
    void *calledBuffer = std::get<void *>(param.params[1]);
    int readLen = std::get<int>(param.params[2]);
    sock_info_itr sock_info_itr = find_sock_info(pid, fd);

    if (sock_info_itr == sock_table.end()) {
      returnSystemCall(syscallUUID, -1);
      break;
    }
    struct sock_info* sock_info = *sock_info_itr;

    // If status of the socket is not ESTAB, return
    if (sock_info->status != Status::ESTAB) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    if (sock_info->recvSpace->bufferStatus == BufferStatus::BUFFERFILLED) {
      int dataSize = BUFFER_SIZE - sock_info->recvSpace->restSpace;
      // Case 1: Read Length is less than dataSize
      if (readLen < dataSize) {
        if (dataSize - sock_info->recvSpace->recv_base > readLen)
          memcpy(calledBuffer, sock_info->recvSpace->buffer + sock_info->recvSpace->recv_base, readLen);
        else
          memcpy(calledBuffer, sock_info->recvSpace->buffer + sock_info->recvSpace->recv_base, dataSize - sock_info->recvSpace->recv_base);
      
        memset(&sock_info->recvSpace->buffer, 0, sizeof(sock_info->recvSpace->buffer));
        returnSystemCall(syscallUUID, readLen);
        sock_info->recvSpace->recv_base += readLen;
        if (sock_info->recvSpace->recv_base >= dataSize) {
          sock_info->recvSpace->expect_seq += dataSize;
          sock_info->recvSpace->recv_base = 0;
        }
      }
      // Case 2: DataSize is less than Read Wait Length (or equal)
      else {
        memcpy(calledBuffer, sock_info->recvSpace->buffer + sock_info->recvSpace->recv_base, dataSize - sock_info->recvSpace->recv_base);
        memset(&sock_info->recvSpace->buffer, 0, sizeof(sock_info->recvSpace->buffer));
        returnSystemCall(syscallUUID, dataSize - sock_info->recvSpace->recv_base);
        sock_info->recvSpace->expect_seq += dataSize;
        sock_info->recvSpace->restSpace = BUFFER_SIZE;
        sock_info->recvSpace->recv_base = 0;
      }
      sock_info->recvSpace->bufferStatus = BufferStatus::NORMAL;
      ack_received_packet(sock_info->recvSpace->recv_pkt, sock_info);
      free(sock_info->recvSpace->recv_pkt);
      sock_info->recvSpace->recv_pkt = NULL;
    }
    else {
      sock_info->recvSpace->bufferStatus = BufferStatus::WAITING;
      sock_info->recvSpace->waitBuffer = calledBuffer;
      sock_info->recvSpace->waitUUID = syscallUUID;
      sock_info->recvSpace->waitLen = readLen;
    }

    break;
  }
  case WRITE: {
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    int fd = std::get<int>(param.params[0]);
    char* param_write_buffer = (char*) std::get<void *>(param.params[1]);
    int writeLen = std::get<int>(param.params[2]), buffer_ptr_cnt = 0;
    sock_info_itr sock_info_itr = find_sock_info(pid, fd);
    struct sock_info* sock_info = *sock_info_itr;
    char *buffer_ptr, *current_buffer_begin;
    SyscallQueueItem *writeQueueItem = (SyscallQueueItem *) malloc(sizeof(struct SyscallQueueItem));
    
    writeQueueItem->pid = pid;
    writeQueueItem->syscallUUID = syscallUUID;
    writeQueueItem->fd = fd;
    writeQueueItem->write_buffer = (char *) malloc(writeLen);
    memcpy(writeQueueItem->write_buffer, param_write_buffer, writeLen);
    writeQueueItem->writeLen = writeLen;

    return writeHandler(syscallUUID, pid, writeQueueItem);
  }
  case CONNECT: {
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    int fd = std::get<int>(param.params[0]);
    sock_info_itr sock_info_itr = find_sock_info(pid, fd);
    if (sock_info_itr == sock_table.end()) {
      returnSystemCall(syscallUUID, -1);
      break;
    }
    struct sock_info* sock_info = *sock_info_itr;
    struct sockaddr_in* param_addr =
      (struct sockaddr_in *) static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    ipv4_t dstIp = NetworkUtil::UINT64ToArray<sizeof(uint32_t)>((uint64_t) param_addr->sin_addr.s_addr);

    uint16_t port;
    if (sock_info->my_sockaddr != NULL && sock_info->my_sockaddr->sin_port > 0) {
      port = sock_info->my_sockaddr->sin_port;
    } else {
      using_resource_itr using_resource_itr;
      bool isDuplicate;
      // Give a random port.
      do {
        isDuplicate = false;
        srand((unsigned int) time(NULL));
        port = (in_port_t) (rand() % 0x10000);

        if (port < 1024) // Escape well-known port(0~1023)
          continue;

        port = htons(port);
        for (using_resource_itr = using_resource_list.begin(); using_resource_itr != using_resource_list.end(); ++using_resource_itr) {
          if ((*using_resource_itr)->port == port) {
            isDuplicate = true;
            break;
          }
        }
      } while (isDuplicate);

      struct UsingResourceInfo* using_resource_info = (struct UsingResourceInfo *) malloc((sizeof(struct UsingResourceInfo)));
      if (sock_info == NULL) {
        printf("Error: can't allocate memory(using_resource_info)\n");
        returnSystemCall(syscallUUID, -1);
        break;
      }
      using_resource_info->fd = fd;
      using_resource_info->pid = pid;
      using_resource_info->port = port;
      using_resource_info->syscalUUID = syscallUUID;
      using_resource_list.push_back(using_resource_info);
    }

    ipv4_t _ip = getIPAddr((uint16_t) getRoutingTable(dstIp)).value();

    u_int32_t myIp = NetworkUtil::arrayToUINT64(_ip);
    Packet synPkt (54);
    setPacketSrcDst(&synPkt, &myIp, &port, &param_addr->sin_addr.s_addr, &param_addr->sin_port);
    
    sock_info->my_sockaddr = get_new_sockaddr_in(myIp, port);
    sock_info->peer_sockaddr = get_new_sockaddr_in(param_addr->sin_addr.s_addr, param_addr->sin_port);
    sock_info->connect_syscallUUID = syscallUUID;

    if (sock_info->my_sockaddr == NULL || sock_info->peer_sockaddr == NULL) {
      if (sock_info->peer_sockaddr != NULL) { free(sock_info->peer_sockaddr); }
      free(sock_info->peer_sockaddr);
      return returnSystemCall(syscallUUID, -1);
    }

    uint8_t tcp_len = 5 << 4;
    uint16_t window_size = htons(1);
    u_int32_t seq_num = getRandomSequnceNumber();
    synPkt.writeData(SEGMENT_OFFSET + 12, &tcp_len, 1);

    synPkt.writeData(SEGMENT_OFFSET + 4, &seq_num, 4);
    set_packet_flags(&synPkt, TH_SYN);
    synPkt.writeData(SEGMENT_OFFSET + 14, &window_size, 2);

    set_packet_checksum(&synPkt, myIp, param_addr->sin_addr.s_addr);

    sendPacket("IPv4", std::move(synPkt));
    sock_info->status = Status::SYN_SENT;
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

    if (sock_info == NULL) {
      printf("Error: can't allocate memory(sockaddr_in)\n");
      returnSystemCall(syscallUUID, -1);
      break;
    }

    sock_info->my_sockaddr = get_new_sockaddr_in(param_addr->sin_addr.s_addr, param_addr->sin_port);

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
    if (sockaddr_in == NULL) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

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
    if (peerAddr_in == NULL) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

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

bool isTargetSock(struct kens_sockaddr_in *sockaddr_in, uint32_t target_ip, uint16_t target_port, bool strict = false) {
  return sockaddr_in != NULL
          && sockaddr_in->sin_port == target_port
          && ((!strict && sockaddr_in->sin_addr == 0) || sockaddr_in->sin_addr == target_ip);
}

/*
  ack_received_packet:
    When receiver receive data, send acknowledge packet to sender.
    The acknowledge packet has new ack number which is added as data size.
    New ack number is already adjusted in `expect_seq`.
*/
void TCPAssignment::ack_received_packet(Packet *packet, struct sock_info *sock_info) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  uint32_t ack_num, new_seq_num;

  Packet ackPkt (54);
  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);
  setPacketSrcDst(&ackPkt, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
  packet->readData(SEGMENT_OFFSET+8, &ack_num, 4);
  new_seq_num = htonl(sock_info->recvSpace->expect_seq);

  ackPkt.writeData(SEGMENT_OFFSET+4, &ack_num, 4);
  ackPkt.writeData(SEGMENT_OFFSET+8, &new_seq_num, 4);
  ackPkt.writeData(SEGMENT_OFFSET+16, &BUFFER_SIZE, 2);
  set_packet_flags(&ackPkt, TH_ACK);
  set_packet_checksum(&ackPkt, income_dst_ip, income_src_ip);

  sendPacket("IPv4", std::move(ackPkt));
}

void TCPAssignment::handleSynAckPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  Packet response_packet = packet->clone();
  sock_info_itr itr;
  struct sock_info *sock_info;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);
  setPacketSrcDst(&response_packet, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);

  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    sock_info = *itr;
    if (isTargetSock(sock_info->my_sockaddr, income_dst_ip, income_dst_port)
        && isTargetSock(sock_info->peer_sockaddr, income_src_ip, income_src_port, true))
    {
      break;
    }
  }
  if (itr == sock_table.end()) {
    return;
  }

  if (sock_info->status == Status::SYN_SENT) {
    sock_info->status = Status::ESTAB;
    if ((sock_info->recvSpace = (struct RecvSpace *) malloc(sizeof(struct RecvSpace))) == NULL) {
      printf("Error: In handleSynAckPacket, can't allocate memory\n");
      return;
    };
    if ((sock_info->sendSpace = (struct SendSpace *) malloc(sizeof(struct SendSpace))) == NULL) {
      printf("Error: In handleSynAckPacket, can't allocate memory\n");
      return;
    }

    memset(sock_info->sendSpace->buffer, 0, sizeof(sock_info->sendSpace->buffer));
    sock_info->sendSpace->next_write = sock_info->sendSpace->buffer;
    sock_info->sendSpace->sent_packet_list = new std::list<struct PacketNode*>();
    sock_info->sendSpace->waiting_write_list = new std::list<struct SyscallQueueItem*>();

    sock_info->recvSpace->bufferStatus = BufferStatus::NORMAL;
    sock_info->recvSpace->waitBuffer = NULL;
    sock_info->recvSpace->waitLen = 0;
    sock_info->recvSpace->waitUUID = -1;
    sock_info->recvSpace->restSpace = BUFFER_SIZE;
    sock_info->recvSpace->expect_seq = get_seq_number(packet);
    sock_info->recvSpace->recv_base = 0;
    sock_info->recvSpace->expect_seq += 1;
    sock_info->recvSpace->recv_pkt = NULL;
  
    set_packet_flags(&response_packet, TH_ACK);
    set_handshake_seqack_number(packet, &response_packet, TH_ACK);
    set_packet_checksum(&response_packet, income_dst_ip, income_src_ip);

    sock_info->my_seq_base = get_seq_number(&response_packet);
    sock_info->peer_seq_base = get_ack_number(&response_packet);

    sendPacket("IPv4", std::move(response_packet));
    returnSystemCall(sock_info->connect_syscallUUID, 0);
    sock_info->connect_syscallUUID = 0;
    return;
  }
}

void TCPAssignment::handleSynPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  sock_info_itr itr;
  struct sock_info* sock_info;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    sock_info = *itr;
    if (isTargetSock(sock_info->my_sockaddr, income_dst_ip, income_dst_port)) {
      break;
    }
  }

  if (itr == sock_table.end()) {
    return;
  }

  // Server: initiallize TCP connection (1st step of 3-way handshake)
  if (sock_info->status == Status::LISTEN) {
    Packet response_packet = packet->clone();
    struct sock_info* new_sock_info;

    setPacketSrcDst(&response_packet, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
    
    // backlog count check
    if (sock_info->backlog <= sock_info->backlog_list->size()) {
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
    new_sock_info->peer_sockaddr->sin_family = AF_INET;

    sock_table.push_back(new_sock_info);
    sock_info->backlog_list->push_back(new_sock_info);

    set_packet_flags(&response_packet, TH_ACK | TH_SYN);
    set_handshake_seqack_number(packet, &response_packet, TH_ACK | TH_SYN);
    set_packet_checksum(&response_packet, income_dst_ip, income_src_ip);

    sendPacket("IPv4", std::move(response_packet));
  }

  return;
}

void TCPAssignment::handleAckPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  Packet packet_to_client = packet->clone();
  struct sock_info *sock_info, *parent_sock_info, *estab_sock_info = NULL;
  struct SyscallQueueItem *accept_queue_item;
  sock_info_itr itr, parent_sock_itr;
  syscall_queue_itr accept_queue_itr;
  packet_node_itr packet_node_itr;
  size_t dataSize = -1;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  // First find parent socket by income_dst_ip and income_dst_port
  for (itr = sock_table.begin(); itr != sock_table.end(); ++itr) {
    parent_sock_info = *itr;
    if (isTargetSock(parent_sock_info->my_sockaddr, income_dst_ip, income_dst_port))
    {
      break;
    }
  }

  if (itr == sock_table.end()) { return; }

  // If there is ESTAB sock_info, allocate it as `estab_sock_info`
  if (parent_sock_info->status == Status::ESTAB) {
    estab_sock_info = parent_sock_info;
  }
  else if (parent_sock_info->status == Status::LISTEN) {
    for (parent_sock_itr = parent_sock_info->child_sock_list->begin(); parent_sock_itr != parent_sock_info->child_sock_list->end(); ++parent_sock_itr) {
      sock_info = *parent_sock_itr;
      if (isTargetSock(sock_info->peer_sockaddr, income_src_ip, income_src_port, true)) {
        break;
      }
    }
    if (parent_sock_itr != parent_sock_info->child_sock_list->end()) {
      estab_sock_info = sock_info;
    }
  }

  // If there is ESTAB sock_info, run this code.
  if (estab_sock_info != NULL) {
    dataSize = packet->getSize() - DATA_OFFSET;
    uint32_t seq_num = get_seq_number(packet);
    uint32_t ack_num = get_ack_number(packet);
    // No data Packet
    if (dataSize <= 0)
      return;
    
    else { // Handle Data Packet (Receive)
      if (estab_sock_info->recvSpace->bufferStatus == BufferStatus::WAITING) {
        // There is no space for data or its seq number is not expected sequence number. So send packet with rcwd
        if (estab_sock_info->recvSpace->restSpace < dataSize || estab_sock_info->recvSpace->expect_seq != seq_num) {
          ack_received_packet(packet, estab_sock_info);
        }
        else {
          packet->readData(DATA_OFFSET, &estab_sock_info->recvSpace->buffer, dataSize);
          // Case 1: Read Wait Length is less than dataSize
          if (estab_sock_info->recvSpace->waitLen < dataSize) {
            if (dataSize - estab_sock_info->recvSpace->recv_base > estab_sock_info->recvSpace->waitLen)
              memcpy(estab_sock_info->recvSpace->waitBuffer, estab_sock_info->recvSpace->buffer + estab_sock_info->recvSpace->recv_base, estab_sock_info->recvSpace->waitLen);
            else
              memcpy(estab_sock_info->recvSpace->waitBuffer, estab_sock_info->recvSpace->buffer + estab_sock_info->recvSpace->recv_base, dataSize - estab_sock_info->recvSpace->recv_base);
            memset(&estab_sock_info->recvSpace->buffer, 0, sizeof(estab_sock_info->recvSpace->buffer));
            returnSystemCall(estab_sock_info->recvSpace->waitUUID, estab_sock_info->recvSpace->waitLen);
            estab_sock_info->recvSpace->recv_base += estab_sock_info->recvSpace->waitLen;
            if (estab_sock_info->recvSpace->recv_base >= dataSize) {
              estab_sock_info->recvSpace->recv_base = 0;
              estab_sock_info->recvSpace->expect_seq += dataSize;
            }
          }
          // Case 2: DataSize is less than Read Wait Length (or equal)
          else {
            memcpy(estab_sock_info->recvSpace->waitBuffer, estab_sock_info->recvSpace->buffer + estab_sock_info->recvSpace->recv_base, dataSize - estab_sock_info->recvSpace->recv_base);
            memset(&estab_sock_info->recvSpace->buffer, 0, sizeof(estab_sock_info->recvSpace->buffer));
            returnSystemCall(estab_sock_info->recvSpace->waitUUID, dataSize - estab_sock_info->recvSpace->recv_base);
            estab_sock_info->recvSpace->expect_seq += dataSize;
            estab_sock_info->recvSpace->recv_base = 0;
          }
          estab_sock_info->recvSpace->bufferStatus = BufferStatus::NORMAL;
          estab_sock_info->recvSpace->waitBuffer = NULL;
          estab_sock_info->recvSpace->waitLen = -1;
          estab_sock_info->recvSpace->waitUUID = -1;

          // send Packet to sender
          ack_received_packet(packet, estab_sock_info);
        }
      }
      else if (estab_sock_info->recvSpace->bufferStatus == BufferStatus::NORMAL) {
        // There is no space for data or its seq number is not expected sequence number. So send packet with rcwd
        if (estab_sock_info->recvSpace->restSpace < dataSize || estab_sock_info->recvSpace->expect_seq != seq_num) {
          ack_received_packet(packet, estab_sock_info);
          return;
        }
        packet->readData(DATA_OFFSET, &estab_sock_info->recvSpace->buffer, dataSize);
        estab_sock_info->recvSpace->restSpace -= dataSize;
        estab_sock_info->recvSpace->bufferStatus = BufferStatus::BUFFERFILLED;
        Packet *recv_pkt = (Packet *) malloc(sizeof(Packet));
        recv_pkt = packet;
        estab_sock_info->recvSpace->recv_pkt = recv_pkt;
      }
      return;
    }
  }

  if ((*itr)->status == Status::ESTAB) {
    // printf("ack arrive\n");
    bool acked = false;
    uint32_t seq_num = get_seq_number(packet);
    uint32_t ack_num = get_ack_number(packet);
    sock_info = *itr;

    for (packet_node_itr = sock_info->sendSpace->sent_packet_list->begin();
          packet_node_itr != sock_info->sendSpace->sent_packet_list->end(); ) {
      PacketNode *packetNode = *packet_node_itr;
      if (packetNode->seq_num < ack_num) {
        memset(packetNode->buffer_ptr, 0, packetNode->buffer_size);
        // packetNode->packet->clearContext();
        free(packetNode);
        packet_node_itr = sock_info->sendSpace->sent_packet_list->erase(packet_node_itr);
        acked = true;
      } else { ++packet_node_itr; }
    }

    if (acked && sock_info->sendSpace->waiting_write_list->size() > 0) {
      syscall_queue_itr write_queue_itr = sock_info->sendSpace->waiting_write_list->begin();
      struct SyscallQueueItem *writeQueueItem = *write_queue_itr;
      sock_info->sendSpace->waiting_write_list->erase(write_queue_itr);
      // printf("next write pending\n");
      writeHandler(writeQueueItem->syscallUUID, writeQueueItem->pid, writeQueueItem);
    }
  } else if (parent_sock_info->status == Status::LISTEN) {
    if (parent_sock_info->backlog_list->size() == 0) { return; }

    // Filter by client IP and port
    for (itr = parent_sock_info->backlog_list->begin(); itr != parent_sock_info->backlog_list->end(); ++itr) {
      sock_info = *itr;
      if (isTargetSock(sock_info->peer_sockaddr, income_src_ip, income_src_port, true)) {
        break;
      }
    }
    if (itr == parent_sock_info->backlog_list->end()) { return; }
    
    parent_sock_info->backlog_list->erase(itr);

    sock_info->status = Status::ESTAB;
    if ((sock_info->recvSpace = (struct RecvSpace *) malloc(sizeof(struct RecvSpace))) == NULL) {
      printf("Error: In handleSynAckPacket, can't allocate memory\n");
      return;
    };
    if ((sock_info->sendSpace = (struct SendSpace *) malloc(sizeof(struct SendSpace))) == NULL) {
      printf("Error: In handleSynAckPacket, can't allocate memory\n");
      return;
    }
    memset(sock_info->sendSpace->buffer, 0, sizeof(sock_info->sendSpace->buffer));
    sock_info->sendSpace->next_write = sock_info->sendSpace->buffer;
    sock_info->sendSpace->sent_packet_list = new std::list<struct PacketNode*>();
    sock_info->sendSpace->waiting_write_list = new std::list<struct SyscallQueueItem*>();
    sock_info->my_seq_base = get_ack_number(packet);
    sock_info->peer_seq_base = get_seq_number(packet);

    sock_info->recvSpace->bufferStatus = BufferStatus::NORMAL;
    sock_info->recvSpace->waitBuffer = NULL;
    sock_info->recvSpace->waitLen = 0;
    sock_info->recvSpace->waitUUID = -1;
    sock_info->recvSpace->restSpace = BUFFER_SIZE;
    sock_info->recvSpace->expect_seq = get_seq_number(packet);
    sock_info->recvSpace->recv_base = 0;
    sock_info->recvSpace->recv_pkt = NULL;
    parent_sock_info->child_sock_list->push_back(sock_info);

    if (accept_queue.size() > 0) {
      for (accept_queue_itr = accept_queue.begin(); accept_queue_itr != accept_queue.end(); ++accept_queue_itr) {
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
    set_packet_flags(&packet_to_client, TH_ACK);
    set_handshake_seqack_number(packet, &packet_to_client, TH_ACK);
    set_packet_checksum(&packet_to_client, income_dst_ip, income_src_ip);
    
    sendPacket("IPv4", std::move(packet_to_client));
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  if (isSynAckPacket(&packet)) {
    return handleSynAckPacket(fromModule, &packet);
  } else if (isSynPacket(&packet)) {
    return handleSynPacket(fromModule, &packet);
  } else if (isAckPacket(&packet)) {
    return handleAckPacket(fromModule, &packet);
  }
}

void TCPAssignment::timerCallback(std::any payload) {
}

} // namespace E

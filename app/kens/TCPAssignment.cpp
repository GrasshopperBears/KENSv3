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

const int PACKET_OFFSET = 14;
const int SEGMENT_OFFSET = PACKET_OFFSET + 20;
const int DATA_OFFSET = SEGMENT_OFFSET + 20;
const size_t BUFFER_SIZE = 2048;
const size_t MSS = 1500;
const Time DEFAULT_RTT = 100 * 1000 * 1000;

// ------------------enums start------------------
enum Status {
  CLOSED,
  LISTEN,
  SYN_RCVD,
  SYN_SENT,
  ESTAB
};

enum TimerType {
  HANDSHAKE,
  SENT
};
// ------------------enums end------------------

// ----------------structs start----------------
struct RWQueueItem {
  UUID syscallUUID;
  int pid;
  SystemCallInterface::SystemCallParameter *param;
  int fd;
  char* buffer;
  int len;
};

struct SentInfo {
  UUID timer_id;
  uint32_t seq;
  E::Time sent_time;
};

struct SendSpace {
  char buffer[BUFFER_SIZE];
  uint32_t base_seq;
  uint32_t peer_base_seq;
  std::list<RWQueueItem*>* waiting_write_list;
  char *sent_from;
  uint32_t sent_seq;
  char *next_data;
  uint32_t next_data_seq;
  char *write_from;
  uint32_t write_seq;
  std::list<SentInfo*>* sent_packet_list;
};

struct RecvSpace {
  char buffer[BUFFER_SIZE];
  uint32_t base_seq;
  uint32_t peer_base_seq;
  std::list<RWQueueItem*>* waiting_read_list;
  char *next_ret;
  uint32_t next_ret_seq;
  char *rcvd;
  uint32_t rcvd_seq;
};

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
  SendSpace *send_space;
  RecvSpace *recv_space;
  UUID handshake_timer;
  Time estimated_rtt;
  Time dev_rtt;
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

struct UsingResourceInfo {
  uint32_t sin_addr;
  in_port_t port;
  int fd;
  int pid;
  UUID syscalUUID;
};
// ----------------structs end----------------

std::list<sock_info*> sock_table;

// accept_queue is a queue for blocking accept.
// pushed by acceptHandler and poped by handleAckPacket.
std::list<AcceptQueueItem *> accept_queue;

// using_resource_list is a list for checking duplicate info.
std::list<UsingResourceInfo *> using_resource_list;

using sock_info_itr = typename std::list<struct sock_info*>::iterator;
using accept_queue_itr = typename std::list<struct AcceptQueueItem*>::iterator;
using rw_queue_itr = typename std::list<struct RWQueueItem*>::iterator;
using sent_info_itr = typename std::list<struct SentInfo*>::iterator;
using using_resource_itr = typename std::list<struct UsingResourceInfo*>::iterator;
using TimerPayload = typename std::tuple<TimerType, struct sock_info*, Packet>;

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
    AcceptQueueItem *tmp;
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

void TCPAssignment::initialize_packet(Packet *packet, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
                                      uint32_t seq, uint32_t ack, uint16_t rcwd)
{
  uint16_t _rcwd = htons(rcwd);
  setPacketSrcDst(packet, &src_ip, &src_port, &dst_ip, &dst_port);
  set_seq_number(packet, seq);
  set_ack_number(packet, ack);
  set_packet_flags(packet, TH_ACK);
  set_packet_length(packet);
  packet->writeData(SEGMENT_OFFSET + 16, &_rcwd, 2);
}

u_int32_t getRandomSequnceNumber() {
  u_int32_t seq_num;
  srand((unsigned int) time(NULL));
  seq_num = (u_int32_t) (rand() + rand()); // MAX of rand() is 0x7fffffff
  return seq_num;
}

/*
  set_seq_ack_number: Set seq and ack number of res_pkt.
  Parameter "flag":
    TH_ACK | TH_SYN: [server] ---SYNACK---> [client]
    TH_ACK         : [client] ------ACK---> [server] 
*/
void set_seq_ack_number(Packet *req_pkt, Packet *res_pkt, uint flag) {
  uint32_t req_seq, req_ack, new_seq, new_ack;

  req_pkt->readData(SEGMENT_OFFSET+4, &req_seq, 4);
  req_pkt->readData(SEGMENT_OFFSET+8, &req_ack, 4);
  if (flag == (TH_ACK | TH_SYN)) {
    u_int32_t seq_num = getRandomSequnceNumber();
    new_seq = htonl(seq_num);
    new_ack = htonl(ntohl(req_seq)+1);
  }
  else if (flag == TH_ACK) {
    new_seq = req_ack;
    new_ack = htonl(ntohl(req_seq)+1);
  }
  else {
    printf("Invalid flag: %x\n", flag);
    return;
  }
  res_pkt->writeData(SEGMENT_OFFSET+4, &new_seq, 4);
  res_pkt->writeData(SEGMENT_OFFSET+8, &new_ack, 4);
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

void update_rtt(sock_info *sock_info, Time new_rtt) {
  sock_info->dev_rtt = 0.75 * sock_info->dev_rtt + 0.25 * std::abs(long(sock_info->estimated_rtt - new_rtt));
  sock_info->estimated_rtt = 0.875 * sock_info->estimated_rtt + 0.125 * new_rtt;
}

E::Time get_timeout_interval(sock_info *sock_info) {
  return sock_info->estimated_rtt + 4 * sock_info->dev_rtt;
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
  if (accept_queue_item == NULL) {
    return returnSystemCall(syscallUUID, -1);
  }
  accept_queue_item->syscallUUID = syscallUUID;
  accept_queue_item->pid = pid;
  accept_queue_item->param = param;

  accept_queue.push_back(accept_queue_item);
  return;
}

void TCPAssignment::readHandler(UUID syscallUUID, int pid, RWQueueItem *readQueueItem) {
  int fd = readQueueItem->fd;
  char *read_buffer = readQueueItem->buffer;
  int readLen = readQueueItem->len, retReadLen;
  struct RecvSpace *recvSpace;
  size_t free_size, first, second, packet_count;

  sock_info_itr sock_info_itr = find_sock_info(pid, fd);
  struct sock_info* sock_info = *sock_info_itr;

  if (sock_info_itr == sock_table.end() || sock_info->status != Status::ESTAB) {
    free(readQueueItem);
    return returnSystemCall(syscallUUID, -1);
  }

  recvSpace = sock_info->recv_space;
  retReadLen = recvSpace->rcvd_seq - recvSpace->next_ret_seq;

  if (retReadLen == 0) {
    recvSpace->waiting_read_list->push_back(readQueueItem);
    return;
  }
  if (retReadLen > readLen) { retReadLen = readLen; }
  
  if (recvSpace->buffer + BUFFER_SIZE - recvSpace->next_ret >= retReadLen) {
    first = retReadLen;
    second = 0;
  } else {
    first = recvSpace->buffer + BUFFER_SIZE - recvSpace->next_ret;
    second = retReadLen - first;
  }

  memcpy(read_buffer, recvSpace->next_ret, first);
  memcpy(read_buffer + first, recvSpace->buffer, second);

  recvSpace->next_ret += retReadLen;
  if (recvSpace->next_ret >= recvSpace->buffer + BUFFER_SIZE) { recvSpace->next_ret -= BUFFER_SIZE; }
  recvSpace->next_ret_seq += retReadLen;

  free(readQueueItem);

  return returnSystemCall(syscallUUID, retReadLen);
}

void TCPAssignment::writeHandler(UUID syscallUUID, int pid, RWQueueItem *writeQueueItem) {
  int fd = writeQueueItem->fd;
  char *write_buffer = writeQueueItem->buffer, *current_buffer_begin;
  int writeLen = writeQueueItem->len;
  struct SendSpace *sendSpace;
  size_t free_size, first, second, packet_count;

  sock_info_itr sock_info_itr = find_sock_info(pid, fd);
  struct sock_info* sock_info = *sock_info_itr;

  if (sock_info_itr == sock_table.end() || sock_info->status != Status::ESTAB) {
    free(write_buffer);
    free(writeQueueItem);
    return returnSystemCall(syscallUUID, -1);
  }

  sendSpace = sock_info->send_space;
  free_size = BUFFER_SIZE - (sendSpace->write_seq - sendSpace->sent_seq);

  if (free_size < writeLen) {
    sendSpace->waiting_write_list->push_back(writeQueueItem);
    return;
  }

  if (sendSpace->buffer + BUFFER_SIZE - sendSpace->write_from >= writeLen) {
    first = writeLen;
    second = 0;
  } else {
    first = sendSpace->buffer + BUFFER_SIZE - sendSpace->write_from;
    second = writeLen - first;
  }
  memcpy(sendSpace->write_from, write_buffer, first);
  memcpy(sendSpace->buffer, write_buffer + first, second);

  sendSpace->write_from += writeLen;
  if (sendSpace->write_from >= sendSpace->buffer + BUFFER_SIZE) { sendSpace->write_from -= BUFFER_SIZE; }
  sendSpace->write_seq += writeLen;

  free(write_buffer);
  free(writeQueueItem);

  packet_count = writeLen / MSS;
  if (writeLen % MSS > 0) { packet_count++; }

  for (int i = 0; i < packet_count; i++) {
    uint64_t packet_size = MSS, buffer_offset = MSS * i;
    if (writeLen - buffer_offset < MSS) { packet_size = writeLen - buffer_offset; }
    Packet senderPacket(DATA_OFFSET + packet_size);
    uint16_t _rcwd = (BUFFER_SIZE - (sendSpace->write_from - sendSpace->sent_from)) % BUFFER_SIZE;
    initialize_packet(&senderPacket, sock_info->my_sockaddr->sin_addr, sock_info->my_sockaddr->sin_port,
                      sock_info->peer_sockaddr->sin_addr, sock_info->peer_sockaddr->sin_port,
                      sendSpace->next_data_seq + buffer_offset, sendSpace->peer_base_seq, 0);
    senderPacket.writeData(DATA_OFFSET, sendSpace->next_data + buffer_offset, packet_size);
    set_packet_checksum(&senderPacket, sock_info->my_sockaddr->sin_addr, sock_info->peer_sockaddr->sin_addr);

    sendSpace->next_data += writeLen;
    if (sendSpace->next_data >= sendSpace->buffer + BUFFER_SIZE) { sendSpace->next_data -= BUFFER_SIZE; }
    sendSpace->next_data_seq += writeLen;
    sendPacket("IPv4", std::move(senderPacket.clone()));

    TimerPayload timer_payload = std::make_tuple(TimerType::SENT, sock_info, senderPacket);
    SentInfo *sent_info = (SentInfo *) malloc(sizeof(struct SentInfo));
    sendSpace->sent_packet_list->push_back(sent_info);
    sent_info->sent_time = getCurrentTime();
    sent_info->seq = sendSpace->next_data_seq + buffer_offset;
    sent_info->timer_id = addTimer(timer_payload, get_timeout_interval(sock_info));
  }
  return returnSystemCall(syscallUUID, writeLen);
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
    sock_info->send_space = NULL;
    sock_info->recv_space = NULL;
    sock_info->estimated_rtt = DEFAULT_RTT;
    sock_info->dev_rtt = 0;

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

    if (sock_info->send_space != NULL) {
      sent_info_itr sent_info_itr;
      SentInfo *sent_info;
      for (sent_info_itr = sock_info->send_space->sent_packet_list->begin();
            sent_info_itr != sock_info->send_space->sent_packet_list->end();)
      {
        sent_info = *sent_info_itr;
        sent_info_itr = sock_info->send_space->sent_packet_list->erase(sent_info_itr);
        cancelTimer(sent_info->timer_id);
        free(sent_info);
      }

      delete sock_info->send_space->waiting_write_list;
      delete sock_info->send_space->sent_packet_list;
      free(sock_info->send_space);
    }
    if (sock_info->recv_space != NULL) {
      delete sock_info->recv_space->waiting_read_list;
      free(sock_info->recv_space);
    }

    sock_table.erase(sock_info_itr);
    if (sock_info->my_sockaddr != NULL)
      free(sock_info->my_sockaddr);
    if (sock_info->peer_sockaddr != NULL)
      free(sock_info->peer_sockaddr);
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
    char* param_read_buffer = (char*) std::get<void *>(param.params[1]);
    int readLen = std::get<int>(param.params[2]);
    RWQueueItem *readQueueItem = (RWQueueItem *) malloc(sizeof(struct RWQueueItem));
    
    readQueueItem->pid = pid;
    readQueueItem->syscallUUID = syscallUUID;
    readQueueItem->fd = fd;
    readQueueItem->buffer = param_read_buffer;
    readQueueItem->len = readLen;

    return readHandler(syscallUUID, pid, readQueueItem);
  }
  case WRITE: {
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    int fd = std::get<int>(param.params[0]);
    char* param_write_buffer = (char*) std::get<void *>(param.params[1]);
    int writeLen = std::get<int>(param.params[2]);
    RWQueueItem *writeQueueItem = (RWQueueItem *) malloc(sizeof(struct RWQueueItem));
    
    writeQueueItem->pid = pid;
    writeQueueItem->syscallUUID = syscallUUID;
    writeQueueItem->fd = fd;
    writeQueueItem->buffer = (char *) malloc(writeLen);
    memcpy(writeQueueItem->buffer, param_write_buffer, writeLen);
    writeQueueItem->len = writeLen;

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

    // TODO: 포트 및 routingTable 관리
    uint16_t port;
    if (sock_info->my_sockaddr != NULL && sock_info->my_sockaddr->sin_port > 0) {
      port = sock_info->my_sockaddr->sin_port;
    } else {
      using_resource_itr using_resource_itr;
      bool isDuplicate;
      // FIXME: Give a random port.
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

    sendPacket("IPv4", std::move(synPkt.clone()));

    std::tuple<TimerType, struct sock_info*, Packet> payload =
      std::make_tuple(TimerType::HANDSHAKE, sock_info, synPkt);
    sock_info->handshake_timer = addTimer(payload, get_timeout_interval(sock_info));

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
  dst->parent_sock = src;
  dst->pid = src->pid;
  dst->status = Status::SYN_RCVD;
  dst->send_space = NULL;
  dst->recv_space = NULL;
  dst->estimated_rtt = DEFAULT_RTT;
  dst->dev_rtt = 0;
}

bool isTargetSock(struct kens_sockaddr_in *sockaddr_in, uint32_t target_ip, uint16_t target_port, bool strict = false) {
  return sockaddr_in != NULL
          && sockaddr_in->sin_port == target_port
          && ((!strict && sockaddr_in->sin_addr == 0) || sockaddr_in->sin_addr == target_ip);
}

void initSendRcvdSpace(sock_info *sock_info, uint32_t send_base_seq, uint32_t recv_base_seq, uint32_t recv_peer_seq) {
  sock_info->send_space = (SendSpace *) malloc(sizeof(struct SendSpace));
  sock_info->send_space->base_seq = send_base_seq;
  sock_info->send_space->sent_from = sock_info->send_space->buffer;
  sock_info->send_space->sent_seq = sock_info->send_space->base_seq;
  sock_info->send_space->next_data = sock_info->send_space->buffer;
  sock_info->send_space->next_data_seq = sock_info->send_space->base_seq;
  sock_info->send_space->write_from = sock_info->send_space->buffer;
  sock_info->send_space->write_seq = sock_info->send_space->base_seq;
  sock_info->send_space->waiting_write_list = new std::list<struct RWQueueItem*>();
  sock_info->send_space->sent_packet_list = new std::list<struct SentInfo*>();

  sock_info->recv_space = (RecvSpace *) malloc(sizeof(struct RecvSpace));
  sock_info->recv_space->base_seq = recv_base_seq;
  sock_info->recv_space->peer_base_seq = recv_peer_seq;
  sock_info->recv_space->next_ret = sock_info->recv_space->buffer;
  sock_info->recv_space->next_ret_seq = sock_info->recv_space->base_seq;
  sock_info->recv_space->rcvd = sock_info->recv_space->buffer;
  sock_info->recv_space->rcvd_seq = sock_info->recv_space->base_seq;
  sock_info->recv_space->waiting_read_list = new std::list<struct RWQueueItem*>();
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
    cancelTimer(sock_info->handshake_timer);

    set_packet_flags(&response_packet, TH_ACK);
    set_seq_ack_number(packet, &response_packet, TH_ACK);
    set_packet_checksum(&response_packet, income_dst_ip, income_src_ip);

    initSendRcvdSpace(sock_info, get_ack_number(packet), get_ack_number(&response_packet), get_seq_number(&response_packet));

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
    Packet response_packet = packet->clone(); // TODO: more than clone
    struct sock_info* new_sock_info;

    setPacketSrcDst(&response_packet, &income_dst_ip, &income_dst_port, &income_src_ip, &income_src_port);
    
    // backlog count check
    if (sock_info->backlog <= sock_info->backlog_list->size()) {
      // 무시 혹은 RST flag set
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

    new_sock_info->my_sockaddr->sin_addr = income_dst_ip;
    new_sock_info->my_sockaddr->sin_port = income_dst_port;
    new_sock_info->my_sockaddr->sin_len = sizeof(struct sockaddr_in);
    new_sock_info->my_sockaddr->sin_family = AF_INET;

    new_sock_info->peer_sockaddr->sin_addr = income_src_ip;
    new_sock_info->peer_sockaddr->sin_port = income_src_port;
    new_sock_info->peer_sockaddr->sin_len = sizeof(struct sockaddr_in);
    new_sock_info->peer_sockaddr->sin_family = AF_INET;

    sock_table.push_back(new_sock_info);
    sock_info->backlog_list->push_back(new_sock_info);

    set_packet_flags(&response_packet, TH_ACK | TH_SYN);
    set_seq_ack_number(packet, &response_packet, TH_ACK | TH_SYN);
    set_packet_checksum(&response_packet, income_dst_ip, income_src_ip);

    sendPacket("IPv4", std::move(response_packet.clone()));

    std::tuple<TimerType, struct sock_info*, Packet> payload =
      std::make_tuple(TimerType::HANDSHAKE, new_sock_info, response_packet);
    new_sock_info->handshake_timer = addTimer(payload, get_timeout_interval(sock_info));
  }

  return;
}

void TCPAssignment::handleAckPacket(std::string fromModule, Packet *packet) {
  uint32_t income_src_ip, income_dst_ip;
  uint16_t income_src_port, income_dst_port;
  Packet packet_to_client = packet->clone();
  struct sock_info *sock_info, *parent_sock_info, *estab_sock_info = NULL;
  struct AcceptQueueItem *accept_queue_item;
  sock_info_itr itr, estab_sock_itr, parent_sock_itr;
  accept_queue_itr accept_queue_itr;

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

  if (parent_sock_info->status == Status::ESTAB) {
    estab_sock_info = parent_sock_info;
  }
  else if (parent_sock_info->status == Status::LISTEN) {
    for (estab_sock_itr = parent_sock_info->child_sock_list->begin(); estab_sock_itr != parent_sock_info->child_sock_list->end(); ++estab_sock_itr) {
      sock_info = *estab_sock_itr;
      if (isTargetSock(sock_info->peer_sockaddr, income_src_ip, income_src_port, true)) {
        break;
      }
    }
    if (estab_sock_itr != parent_sock_info->child_sock_list->end()) {
      estab_sock_info = sock_info;
    }
  }

  if (estab_sock_info != NULL) {
    uint32_t seq_num = get_seq_number(packet), ack_num = get_ack_number(packet), data_size = packet->getSize() - DATA_OFFSET;
    int acked_size;
    sock_info = estab_sock_info;

    // handle read
    if (data_size > 0) {
      RecvSpace *recvSpace = sock_info->recv_space;
      size_t first, second;
      if (seq_num < recvSpace->rcvd_seq) {
        Packet response_packet = Packet(DATA_OFFSET);
        uint16_t _rcwd = (BUFFER_SIZE - (recvSpace->rcvd - recvSpace->next_ret)) % BUFFER_SIZE;
        initialize_packet(&response_packet, income_dst_ip, income_dst_port, income_src_ip, income_src_port,
                          sock_info->send_space->base_seq, recvSpace->rcvd_seq, _rcwd);
        set_packet_checksum(&response_packet, sock_info->my_sockaddr->sin_addr, sock_info->peer_sockaddr->sin_addr);
        sendPacket("IPv4", std::move(response_packet));
        return;
      }

      if (recvSpace->buffer + BUFFER_SIZE - recvSpace->rcvd >= data_size) {
        first = data_size;
        second = 0;
      } else {
        first = recvSpace->buffer + BUFFER_SIZE - recvSpace->rcvd;
        second = data_size - first;
      }

      packet->readData(DATA_OFFSET, recvSpace->rcvd, first);
      packet->readData(DATA_OFFSET + first, recvSpace->buffer, second);

      recvSpace->rcvd_seq += data_size;
      recvSpace->rcvd += data_size;
      if (recvSpace->rcvd >= recvSpace->buffer + BUFFER_SIZE) {
        recvSpace->rcvd -= BUFFER_SIZE;
      }
      
      Packet response_packet = Packet(DATA_OFFSET);
      uint16_t _rcwd = (BUFFER_SIZE - (recvSpace->rcvd - recvSpace->next_ret)) % BUFFER_SIZE;
      initialize_packet(&response_packet, income_dst_ip, income_dst_port, income_src_ip, income_src_port,
                        sock_info->send_space->base_seq, recvSpace->rcvd_seq, _rcwd);
      set_packet_checksum(&response_packet, sock_info->my_sockaddr->sin_addr, sock_info->peer_sockaddr->sin_addr);

      if (sock_info->recv_space->waiting_read_list->size() > 0) {
        rw_queue_itr read_queue_itr = sock_info->recv_space->waiting_read_list->begin();
        struct RWQueueItem *readQueueItem = *read_queue_itr;
        sock_info->recv_space->waiting_read_list->erase(read_queue_itr);
        readHandler(readQueueItem->syscallUUID, readQueueItem->pid, readQueueItem);
      }

      sendPacket("IPv4", std::move(response_packet));
      return;
    }

    // handle write
    acked_size = ack_num - sock_info->send_space->sent_seq;
    if (acked_size > 0) {
      sock_info->send_space->sent_from += acked_size;
      if (sock_info->send_space->sent_from >= sock_info->send_space->buffer + BUFFER_SIZE) {
        sock_info->send_space->sent_from -= BUFFER_SIZE;
      }
      sock_info->send_space->sent_seq += acked_size;

      sent_info_itr sent_info_itr;
      SentInfo *sent_info;
      for (sent_info_itr = sock_info->send_space->sent_packet_list->begin();
            sent_info_itr != sock_info->send_space->sent_packet_list->end();)
      {
        sent_info = *sent_info_itr;
        if (sent_info->seq < ack_num) {
          cancelTimer(sent_info->timer_id);
          update_rtt(sock_info, getCurrentTime() - sent_info->sent_time);
          sent_info_itr = sock_info->send_space->sent_packet_list->erase(sent_info_itr);
          free(sent_info);
        } else {
          sent_info_itr++;
        }
      }

      if (sock_info->send_space->waiting_write_list->size() > 0) {
        rw_queue_itr write_queue_itr = sock_info->send_space->waiting_write_list->begin();
        struct RWQueueItem *writeQueueItem = *write_queue_itr;
        sock_info->send_space->waiting_write_list->erase(write_queue_itr);
        writeHandler(writeQueueItem->syscallUUID, writeQueueItem->pid, writeQueueItem);
      }
    }
    return;
  }

  if (parent_sock_info->status == Status::LISTEN) {
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
    cancelTimer(sock_info->handshake_timer);

    initSendRcvdSpace(sock_info, get_ack_number(packet), get_seq_number(packet), get_ack_number(packet));

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
    set_seq_ack_number(packet, &packet_to_client, TH_ACK);
    set_packet_checksum(&packet_to_client, income_dst_ip, income_src_ip);
    
    sendPacket("IPv4", std::move(packet_to_client));
  }
}

bool isValidPacket(Packet *packet) {
  uint16_t income_src_port, income_dst_port;
  uint32_t income_src_ip, income_dst_ip;
  uint64_t packet_length = packet->getSize() - SEGMENT_OFFSET;
  char buffer[packet_length];

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);
  packet->readData(SEGMENT_OFFSET, buffer, packet_length);

  uint16_t checksum = NetworkUtil::tcp_sum(income_src_ip, income_dst_ip, (uint8_t *)buffer, packet_length);

  return checksum == 0xFFFF;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  if (!isValidPacket(&packet)) { return; }

  if (isSynAckPacket(&packet)) {
    return handleSynAckPacket(fromModule, &packet);
  } else if (isSynPacket(&packet)) {
    return handleSynPacket(fromModule, &packet);
  } else if (isAckPacket(&packet)) {
    return handleAckPacket(fromModule, &packet);
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  TimerPayload params = std::any_cast<TimerPayload>(payload);
  TimerType timer_type = std::get<0>(params);
  sock_info *sock_info = std::get<1>(params);
  Packet packet = std::get<2>(params);

  if (timer_type == TimerType::HANDSHAKE) {
    sendPacket("IPv4", std::move(packet.clone()));
    sock_info->handshake_timer = addTimer(params, get_timeout_interval(sock_info));
  } else if (timer_type == TimerType::SENT) {
    sent_info_itr sent_info_itr;
    SentInfo *sent_info;
    for (sent_info_itr = sock_info->send_space->sent_packet_list->begin();
          sent_info_itr != sock_info->send_space->sent_packet_list->end();
          sent_info_itr++)
    {
      sent_info = *sent_info_itr;
      if (sent_info->seq == get_seq_number(&packet)) { break; }
    }

    if (sent_info_itr != sock_info->send_space->sent_packet_list->end()) {
      sendPacket("IPv4", std::move(packet.clone()));
      sent_info->sent_time = getCurrentTime();
      sent_info->timer_id = addTimer(payload, get_timeout_interval(sock_info) * 2);
    }
  }
}

} // namespace E

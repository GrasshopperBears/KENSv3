/*
 * E_RoutingAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

#include "RoutingAssignment.hpp"

namespace E {

const int PACKET_OFFSET = 14;
const int SEGMENT_OFFSET = PACKET_OFFSET + 20;
const int DATA_OFFSET = SEGMENT_OFFSET + 8; // UDP header is 8 bytes
const int RIP_HEADER_SIZE = 4;
const int RIP_ENTRY_SIZE = 20;
uint16_t RIP_PORT = 520;
const uint64_t TIME_SECOND = 1000 * 1000 * 1000;

// ------------------enums start------------------



// ------------------enums end------------------

// ----------------structs start----------------
struct pseudoheader {
  uint32_t source;
  uint32_t destination;
  uint8_t zero;
  uint8_t protocol;
  uint16_t length;
};

struct rip_info {
  uint32_t ip;
  uint8_t hops;
  uint16_t cost;  // docs: In RIPv1, the cost is just hop-count
};
// ----------------structs end----------------

std::list<rip_info*> rip_table;

using rip_info_itr = typename std::list<struct rip_info*>::iterator;
using uint16_pair = typename std::pair<uint16_t, uint16_t>;

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {}

RoutingAssignment::~RoutingAssignment() {}

rip_info_itr find_rip_info(uint32_t ipv4) {
  rip_info_itr itr;
  for (itr = rip_table.begin(); itr != rip_table.end(); ++itr) {
    if ((*itr)->ip == ipv4) { break; }
  }
  return itr;
}

void getPacketSrcDst(Packet *packet, uint32_t *src_ip, uint16_t *src_port, uint32_t *dst_ip, uint16_t *dst_port) {
  packet->readData(PACKET_OFFSET + 12, src_ip, 4);
  packet->readData(PACKET_OFFSET + 16, dst_ip, 4);
  packet->readData(SEGMENT_OFFSET, src_port, 2);
  packet->readData(SEGMENT_OFFSET + 2, dst_port, 2);

  *src_ip = ntohl(*src_ip);
  *dst_ip = ntohl(*dst_ip);
  *src_port = ntohs(*src_port);
  *dst_port = ntohs(*dst_port);
}

void setPacketSrcDst(Packet *packet, uint32_t *src_ip, uint16_t *src_port, uint32_t *dst_ip, uint16_t *dst_port) {
  uint32_t src_ip_converted = htonl(*src_ip);
  uint32_t dst_ip_converted = htonl(*dst_ip);
  uint16_t src_port_converted = htons(*src_port);
  uint16_t dst_port_converted = htons(*dst_port);
  
  packet->writeData(PACKET_OFFSET + 12, &src_ip_converted, 4);
  packet->writeData(PACKET_OFFSET + 16, &dst_ip_converted, 4);
  packet->writeData(SEGMENT_OFFSET, &src_port_converted, 2);
  packet->writeData(SEGMENT_OFFSET + 2, &dst_port_converted, 2);
}

uint16_t getPacketTtl(Packet *packet) {
  uint16_t ttl;
  packet->readData(PACKET_OFFSET + 8, &ttl, 1);
  return ttl;
}

void setPacketTtl(Packet *packet, uint16_t ttl) {
  packet->writeData(PACKET_OFFSET + 8, &ttl, 1);
}

uint16_pair get_udp_port(Packet *packet) {
  uint16_t src_port, dst_port;
  uint16_pair ports;

  packet->readData(SEGMENT_OFFSET, &src_port, 2);
  packet->readData(SEGMENT_OFFSET + 2, &dst_port, 2);
  ports = std::make_pair(ntohs(src_port), ntohs(dst_port));
  return ports;
}

void set_udp_port(Packet *packet, uint16_t *src_port, uint16_t *dst_port) {
  uint16_t src_port_converted = htons(*src_port);
  uint16_t dst_port_converted = htons(*dst_port);
  
  packet->writeData(SEGMENT_OFFSET, &src_port_converted, 2);
  packet->writeData(SEGMENT_OFFSET + 2, &dst_port_converted, 2);
}

void set_udp_header_len(Packet *packet, uint16_t header_len) {
  uint16_t header_len_converted = htons(header_len);

  packet->writeData(SEGMENT_OFFSET + 4, &header_len_converted, 2);
}

uint16_t udp_sum(uint32_t source, uint32_t dest, const uint8_t *tcp_seg, size_t length) {
  if (length < 20)
    return 0;
  struct pseudoheader pheader;
  pheader.source = source;
  pheader.destination = dest;
  pheader.zero = 0;
  pheader.protocol = 17;
  pheader.length = length;

  uint32_t sum = NetworkUtil::one_sum((uint8_t *)&pheader, sizeof(pheader));
  sum += NetworkUtil::one_sum(tcp_seg, length);
  sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)sum;
}

void set_packet_checksum(Packet *packet, uint32_t src_ip, uint32_t dst_ip) {
  uint64_t packet_length = packet->getSize() - SEGMENT_OFFSET;
  uint16_t zero = 0;
  int checksum_pos = 6, checksum_size = 2;
  char buffer[packet_length];

  // Init checksum field
  packet->writeData(SEGMENT_OFFSET + checksum_pos, &zero, checksum_size);

  packet->readData(SEGMENT_OFFSET, buffer, packet_length);
  uint16_t checksum = udp_sum(src_ip, dst_ip, (uint8_t *)buffer, packet_length);
  checksum = ~checksum;
  checksum = htons(checksum);
  packet->writeData(SEGMENT_OFFSET + checksum_pos, &checksum, checksum_size);
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

void setRipHeader(Packet *packet, uint8_t command) {
  uint8_t version = 1;
  uint16_t zero = 0;

  packet->writeData(DATA_OFFSET, &command, 1);
  packet->writeData(DATA_OFFSET + 1, &version, 1);
  packet->writeData(DATA_OFFSET + 2, &zero, 2);
}

void getRipHeader(Packet *packet, uint8_t *command, uint8_t *version) {
  packet->readData(DATA_OFFSET, command, 1);
  packet->readData(DATA_OFFSET + 1, version, 1);
}

void setIthRipEntry(Packet *packet, uint8_t idx, uint32_t ip, uint32_t metric, uint16_t addr_fam = 2) {
  uint16_t addr_fam_converted = htons(addr_fam);
  uint32_t entry_offset = DATA_OFFSET + RIP_HEADER_SIZE + RIP_ENTRY_SIZE * idx, zero = 0;
  uint32_t ip_converted = htonl(ip), metric_converted = htonl(metric);

  packet->writeData(entry_offset, &addr_fam_converted, 2);
  packet->writeData(entry_offset + 2, &zero, 2);
  packet->writeData(entry_offset + 4, &ip_converted, 4);
  packet->writeData(entry_offset + 8, &zero, 4);
  packet->writeData(entry_offset + 12, &zero, 4);
  packet->writeData(entry_offset + 16, &metric_converted, 4);
}

void getIthRipEntry(Packet *packet, uint8_t idx, uint32_t *ip, uint32_t *metric, uint16_t *addr_fam) {
  uint32_t entry_offset = DATA_OFFSET + RIP_HEADER_SIZE + RIP_ENTRY_SIZE * idx;

  packet->readData(entry_offset, addr_fam, 2);
  packet->readData(entry_offset + 4, ip, 4);
  packet->readData(entry_offset + 16, metric, 4);

  *addr_fam = ntohs(*addr_fam);
  *ip = ntohl(*ip);
  *metric = ntohl(*metric);
}

void RoutingAssignment::initialize() {
  Packet initial_packet = Packet(DATA_OFFSET + RIP_HEADER_SIZE + RIP_ENTRY_SIZE);
  ipv4_t broadcast_ip = {255, 255, 255, 255};
  ipv4_t ip = getIPAddr((uint16_t) getRoutingTable(broadcast_ip)).value();

  uint32_t src_ip = NetworkUtil::arrayToUINT64(ip);
  uint32_t dst_ip = NetworkUtil::arrayToUINT64(broadcast_ip);

  setPacketSrcDst(&initial_packet, &src_ip, &RIP_PORT, &dst_ip, &RIP_PORT);
  set_udp_header_len(&initial_packet, initial_packet.getSize() - SEGMENT_OFFSET);
  setRipHeader(&initial_packet, 1);
  setIthRipEntry(&initial_packet, 0, 0UL, 16UL, 0UL);
  set_packet_checksum(&initial_packet, src_ip, dst_ip);

  sendPacket("IPv4", std::move(initial_packet));
  addTimer(nullptr, 30UL * TIME_SECOND);
}

void RoutingAssignment::finalize() {
  if (rip_table.size() > 0) {
    rip_info_itr itr = rip_table.begin();
    while (itr != rip_table.end()) {
      itr = rip_table.erase(itr);
    }
  }
}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  // Implement below
  rip_info_itr itr = find_rip_info(NetworkUtil::arrayToUINT64(ipv4));

  if (itr == rip_table.end()) { return -1; }

  return (*itr)->hops;
}

bool isRipPort(Packet *packet) {
  uint16_t income_src_port, income_dst_port;
  uint32_t income_src_ip, income_dst_ip;

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  return income_src_port == RIP_PORT && income_dst_port == RIP_PORT;
}

bool isInitialPacket(Packet *packet) {
  uint32_t ip, metric;
  uint16_t addr_fam, initial_packet_size = DATA_OFFSET + RIP_HEADER_SIZE + RIP_ENTRY_SIZE;
  uint8_t command, version;

  if (packet->getSize() != initial_packet_size) { return false; }

  getRipHeader(packet, &command, &version);
  getIthRipEntry(packet, 0, &ip, &metric, &addr_fam);

  return command == 1 && addr_fam == 0 && ip == 0 && metric == 16;
}

void initialPacketHandler(Packet *packet) {
  uint16_t income_src_port, income_dst_port;
  uint32_t income_src_ip, income_dst_ip;
  rip_info *rip_info = (struct rip_info *) malloc(sizeof(struct rip_info));

  getPacketSrcDst(packet, &income_src_ip, &income_src_port, &income_dst_ip, &income_dst_port);

  rip_info->ip = income_src_ip;
  rip_info->hops = 1;
  rip_info->cost = 1;
  rip_table.push_back(rip_info);
  return;
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  if (!isRipPort(&packet)) { return; }
  if (isInitialPacket(&packet)) { return initialPacketHandler(&packet); }
  // TODO: handle other request packets
}

void RoutingAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E

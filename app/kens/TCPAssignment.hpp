/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

namespace E {

struct RWQueueItem;

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void initialize_packet(Packet *packet, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint32_t seq, uint32_t ack, uint16_t rcwd) final;
  virtual void acceptHandler(UUID syscallUUID, int pid, SystemCallParameter *param) final;
  virtual void readHandler(UUID syscallUUID, int pid, RWQueueItem *readQueueItem) final;
  virtual void writeHandler(UUID syscallUUID, int pid, RWQueueItem *writeQueueItem) final;
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void handleSynAckPacket(std::string fromModule, Packet *packet) final;
  virtual void handleSynPacket(std::string fromModule, Packet *packet) final;
  virtual void handleAckPacket(std::string fromModule, Packet *packet) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
  virtual void setPacketSrcDst(Packet *packet, uint32_t *src_ip, uint16_t *src_port, uint32_t *dst_ip, uint16_t *dst_port) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */

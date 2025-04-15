#include "analyzer.h"
#include "pcap_file_manager.h"
#include "source/common/common/logger.h"
#include "envoy/common/random_generator.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <random>
#include <cstdint>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SnortHttp {

// BaseAnalyzer
BaseAnalyzer::BaseAnalyzer() {
  // Calling generateRandomNumber() can have impact performance. Comment it for now.
  seq_ = 0; // generateRandomNumber();
  ack_ = 0;
  daq_ = nullptr;
}

uint32_t BaseAnalyzer::generateRandomNumber() {
  std::random_device rd;
  std::mt19937 generator(rd());
  std::uniform_int_distribution<uint32_t> distribution(0, UINT32_MAX);

  // Generate a random uint32_t number
  uint32_t randomNumber = distribution(generator);

  return randomNumber;
}

Buffer::OwnedImpl
BaseAnalyzer::createPacket(const void* data, uint64_t size,
                           const Network::Address::InstanceConstSharedPtr& source_address,
                           const Network::Address::InstanceConstSharedPtr& destination_address) {
  // Payload
  const uint8_t* payload = static_cast<const uint8_t*>(data);
  uint64_t payload_length = size;

  // Construct Ethernet header. This might not be required for Snort for analysis.
  struct ether_header eth_header;
  memset(&eth_header, 0, sizeof(eth_header));
  // Set source and destination MAC addresses (dummy values)
  memcpy(eth_header.ether_shost, "\x0a\x02\x02\x02\x02\x01", ETH_ALEN);
  memcpy(eth_header.ether_dhost, "\x0a\x02\x02\x02\x02\x02", ETH_ALEN);
  eth_header.ether_type = htons(ETHERTYPE_IP);

  // Construct IP header
  struct ip ip_hdr;
  memset(&ip_hdr, 0, sizeof(ip_hdr));
  ip_hdr.ip_v = source_address->ip()->version() == Network::Address::IpVersion::v4 ? 4 : 6;
  ip_hdr.ip_hl = 5;    // Header length
  ip_hdr.ip_ttl = 255; // Time to live
  ip_hdr.ip_id = htons(0x1234);
  ip_hdr.ip_p = IPPROTO_TCP; // Protocol
  ip_hdr.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + payload_length);
  ip_hdr.ip_src.s_addr = inet_addr(source_address->ip()->addressAsString().c_str());
  ip_hdr.ip_dst.s_addr = inet_addr(destination_address->ip()->addressAsString().c_str());
  ip_hdr.ip_sum = checksum(reinterpret_cast<uint16_t*>(&ip_hdr), sizeof(struct ip));

  // Construct TCP header
  struct tcphdr tcp_hdr;
  memset(&tcp_hdr, 0, sizeof(tcp_hdr));
  tcp_hdr.th_off = 5; // Data offset
  tcp_hdr.th_flags = TH_PUSH | TH_ACK;
  tcp_hdr.th_win = htons(8192); // Window size
  tcp_hdr.th_sport = htons(source_address->ip()->port());
  tcp_hdr.th_dport = htons(destination_address->ip()->port());

  tcp_hdr.th_seq = htonl(seq_);
  tcp_hdr.th_ack = htonl(ack_);
  seq_ += payload_length; // Increment sequence number by payload length
  tcp_hdr.th_sum = 0;
  tcp_hdr.th_urp = 0;

  // Calculate checksum
  uint8_t pseudo_header[12];
  memcpy(pseudo_header, &ip_hdr.ip_src.s_addr, 4);
  memcpy(pseudo_header + 4, &ip_hdr.ip_dst.s_addr, 4);
  pseudo_header[8] = 0;
  pseudo_header[9] = ip_hdr.ip_p;
  uint16_t tcp_len = htons(sizeof(struct tcphdr) + payload_length);
  memcpy(pseudo_header + 10, &tcp_len, 2);

  uint8_t* tcp_segment = new uint8_t[12 + sizeof(struct tcphdr) + payload_length];
  memcpy(tcp_segment, pseudo_header, 12);
  memcpy(tcp_segment + 12, &tcp_hdr, sizeof(struct tcphdr));
  memcpy(tcp_segment + 12 + sizeof(struct tcphdr), payload, payload_length);

  tcp_hdr.th_sum = checksum(reinterpret_cast<uint16_t*>(tcp_segment),
                            (12 + sizeof(struct tcphdr) + payload_length));

  delete[] tcp_segment;

  // Create packet with header and payload
  Buffer::OwnedImpl packet;
  packet.add(&eth_header, sizeof(eth_header));
  packet.add(&ip_hdr, sizeof(ip_hdr));
  packet.add(&tcp_hdr, sizeof(tcp_hdr));
  packet.add(payload, payload_length);

  return packet;
}

// Calculate checksum
uint16_t BaseAnalyzer::checksum(const uint16_t* buf, int len) {
  int nleft = len;
  uint32_t sum = 0; // Use uint32_t to handle overflow

  // Sum all 16-bit words
  while (nleft > 1) {
    sum += *buf++;
    nleft -= 2;
  }

  // If there's a leftover byte, add it
  if (nleft == 1) {
    sum += *(reinterpret_cast<const uint8_t*>(buf)); // Cast to uint8_t to get the last byte
  }

  // Fold 32-bit sum to 16 bits
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return ~sum;
}

// Request Analyzer
RequestAnalyzer::RequestAnalyzer(bool enable_save_pcap, bool enable_analyze,
                                 const std::string& unix_socket_path)
    : BaseAnalyzer(), enable_save_pcap_(enable_save_pcap), enable_analyze_(enable_analyze),
      unix_socket_path_(unix_socket_path) {

  if (enable_analyze && daq_ == nullptr) {
    ENVOY_LOG(trace, "snort RequestAnalyzer enabled. Creating DAQ manager");
    daq_ = std::make_unique<DaqManager>(unix_socket_path_);
  }
}

// Response Analyzer
ResponseAnalyzer::ResponseAnalyzer(bool enable_save_pcap, bool enable_analyze,
                                   const std::string& unix_socket_path)
    : BaseAnalyzer(), enable_save_pcap_(enable_save_pcap), enable_analyze_(enable_analyze),
      unix_socket_path_(unix_socket_path) {

  if (enable_analyze && daq_ == nullptr) {
    ENVOY_LOG(trace, "snort ResponseAnalyzer enabled. Creating DAQ manager");
    daq_ = std::make_unique<DaqManager>(unix_socket_path_);
  }
}

// Request Analyzer
bool RequestAnalyzer::analyze(const uint8_t* data, size_t size,
                              const Network::Connection& connection) {

  if (!enable_analyze_ && !enable_save_pcap_) {
    ENVOY_LOG_ONCE(trace, "Snort http request analysis and PCAP saving are disabled");
    return true;
  }

  if (data == nullptr || size == 0) {
    ENVOY_LOG(trace, "snort RequestAnalyzer: data is null or size is zero");
    return true; // No data to analyze
  }

  // Get connection source and destination address
  auto source_address = connection.connectionInfoProvider().directRemoteAddress();
  auto destination_address = connection.connectionInfoProvider().directLocalAddress();

  Buffer::OwnedImpl packet = createPacket(data, size, source_address, destination_address);

  // Write packet to PCAP file
  if (enable_save_pcap_) {
    PcapFileManager::getInstance().writeToPcap(
        static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());
  }

  // If analysis using snort is disabled return true.
  if (!enable_analyze_) {
    ENVOY_LOG(trace, "Snort http request analysis is disabled");
    return true;
  }

  // Send packet to snort DAQ for analysis
  bool status = daq_->sendPacketToDaq(
      static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());

  if (status) {
    status = daq_->getVerdictFromDaq();
    if (status) {
      ENVOY_LOG(trace, "Verdict passed for request");
    } else {
      ENVOY_LOG(trace, "Verdict failed for request");
    }
  } else {
    ENVOY_LOG(trace, "Sending request packet to Snort DAQ failed");
  }
  return status;
}

// ResponseAnalyzer
bool ResponseAnalyzer::analyze(const uint8_t* data, size_t size,
                               const Network::Connection& connection) {

  if (!enable_analyze_ && !enable_save_pcap_) {
    ENVOY_LOG_ONCE(trace, "Snort http response analysis and PCAP saving are disabled");
    return true;
  }


  if (data == nullptr || size == 0) {
    ENVOY_LOG(trace, "snort ResponseAnalyzer: data is null or size is zero");
    return true; // No data to analyze
  }

  // Get connection details
  auto source_address = connection.connectionInfoProvider().directLocalAddress();
  auto destination_address = connection.connectionInfoProvider().directRemoteAddress();

  Buffer::OwnedImpl packet = createPacket(data, size, source_address, destination_address);

  // Write packet to PCAP file
  if (enable_save_pcap_) {
    PcapFileManager::getInstance().writeToPcap(
        static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());
  }

  // If analysis using snort is disabled return true.
  if (!enable_analyze_) {
    ENVOY_LOG(trace, "Snort http response analysis is disabled");
    return true;
  }

  // Send packet to snort DAQ for analysis
  bool status = daq_->sendPacketToDaq(
      static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());

  if (status) {
    status = daq_->getVerdictFromDaq();
    if (status) {
      ENVOY_LOG(trace, "Verdict passed for response");
    } else {
      ENVOY_LOG(trace, "Verdict failed for response");
    }
  } else {
    ENVOY_LOG(trace, "Sending response packet to Snort DAQ failed");
  }
  return status;
}

} // namespace SnortHttp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

#include "analyzer.h"
#include "pcap_file_manager.h"
#include "source/common/http/codes.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

namespace Envoy {
namespace Http {

// BaseAnalyzer
std::string BaseAnalyzer::serializeHeaders(const Http::HeaderMap& headers) {
  std::string result;

  // Serialize each header
  headers.iterate([&result](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
    auto key = std::string(header.key().getStringView());
    // Ignore key starting with ":" (e.g: ":authority", ":path", ":status")
    if (key.starts_with(":")) {
      return Http::HeaderMap::Iterate::Continue;
    }
    auto val = std::string(header.value().getStringView());
    result += key + ": " + val + "\r\n";
    return Http::HeaderMap::Iterate::Continue;
  });

  result += "\r\n"; // End of headers

  return result;
}

Buffer::OwnedImpl
BaseAnalyzer::createPacket(const void* data, uint64_t size,
                           const Network::Address::InstanceConstSharedPtr& source_address,
                           const Network::Address::InstanceConstSharedPtr& destination_address) {
  // Payload
  const uint8_t* payload = static_cast<const uint8_t*>(data);
  uint64_t payload_length = size;

  // Construct Ethernet header
  struct ether_header eth_header;
  memset(&eth_header, 0, sizeof(eth_header));
  // Set source and destination MAC addresses (example values)
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
  ip_hdr.ip_sum = checksum(reinterpret_cast<uint16_t *>(&ip_hdr), sizeof(struct ip) / 2);

  // Construct TCP header
  struct tcphdr tcp_hdr;
  memset(&tcp_hdr, 0, sizeof(tcp_hdr));
  tcp_hdr.th_off = 5;           // Data offset
  tcp_hdr.th_flags = TH_ACK;    // TH_ACK
  tcp_hdr.th_win = htons(8192); // Window size
  tcp_hdr.th_sport = htons(source_address->ip()->port());
  tcp_hdr.th_dport = htons(destination_address->ip()->port());

  static uint32_t ack = 0;
  tcp_hdr.th_seq = htonl(0);
  tcp_hdr.th_ack = htonl(ack);
  ack = payload_length;
  tcp_hdr.th_sum = 0;
  tcp_hdr.th_urp = 0;

  // Calculate checksum
  uint8_t pseudo_header[12];
  memcpy(pseudo_header, &ip_hdr.ip_src.s_addr, 4);
  memcpy(pseudo_header + 4, &ip_hdr.ip_dst.s_addr, 4);
  pseudo_header[8] = 0;
  pseudo_header[9] = ip_hdr.ip_p;
  unsigned short tcp_len = htons(sizeof(struct tcphdr) + payload_length);
  memcpy(pseudo_header + 10, &tcp_len, 2);

  uint8_t *tcp_segment = new uint8_t[12 + sizeof(struct tcphdr) + payload_length];
  memcpy(tcp_segment, pseudo_header, 12);
  memcpy(tcp_segment + 12, &tcp_hdr, sizeof(struct tcphdr));
  memcpy(tcp_segment + 12 + sizeof(struct tcphdr), payload, payload_length);

  tcp_hdr.th_sum = checksum(reinterpret_cast<uint16_t *>(tcp_segment),
                            (12 + sizeof(struct tcphdr) + payload_length) / 2);

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
uint16_t BaseAnalyzer::checksum(const uint16_t* buf, size_t nwords) {
  uint64_t sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

// Request Analyzer
std::string RequestAnalyzer::serializeRequestHeaders(const Http::RequestHeaderMap& headers) {
  std::string result;

  // Serialize method and path
  auto method = std::string(headers.getMethodValue());
  auto scheme = std::string(headers.getSchemeValue());
  auto path = std::string(headers.getPathValue());
  auto host = std::string(headers.getHostValue());
  auto protocol = std::string(headers.getProtocolValue());
  if (protocol.empty()) {
    protocol = "HTTP/1.1";
  }

  ENVOY_LOG(
      trace,
      "snort serializeRequestHeaders: method: {}, scheme: {}, path: {}, host: {}, protocol: {}",
      method, scheme, path, host, protocol);

  // Add HTTP request line in payload (e.g:  GET http://example.com/xyz/ HTTP/1.1)
  result += method + " " + scheme + "://" + host + path + " " + protocol + "\r\n";

  // Serialize each header
  result += serializeHeaders(headers);

  ENVOY_LOG(trace, "snort serializeRequestHeaders: result: {}", result);
  return result;
}

std::string RequestAnalyzer::serializeRequestTrailers(const Http::RequestTrailerMap& trailers) {
  return serializeHeaders(trailers);
}

// Response Analyzer
std::string ResponseAnalyzer::serializeResponseHeaders(const Http::ResponseHeaderMap& headers) {
  std::string result;

  // Add HTTP version and status code
  auto status_code = std::string(headers.getStatusValue());
  auto status_code_string =
      std::string(CodeUtility::toString(static_cast<Http::Code>(std::stoi(status_code))));

  // Add HTTP response line in payload (e.g: HTTP/1.1 200 OK)
  result += "HTTP/1.1 " + status_code + " " + status_code_string + "\r\n";

  // Serialize each header
  result += serializeHeaders(headers);

  return result;
}

std::string ResponseAnalyzer::serializeResponseTrailers(const Http::ResponseTrailerMap& trailers) {
  return serializeHeaders(trailers);
}

// Analyzer
bool Analyzer::analyzeRequest(const Buffer::Instance& data, const Http::RequestHeaderMap* headers,
                              const Http::RequestTrailerMap* trailers,
                              const Network::Connection& connection) {

  Buffer::OwnedImpl buffer;
  if (headers) {
    std::string s = serializeRequestHeaders(*headers);
    buffer.add(s);
  }
  if (data.length() > 0) {
    buffer.add(data);
  }
  if (trailers) {
    std::string s = serializeRequestTrailers(*trailers);
    buffer.add(s);
  }

  // Get connection source and destination address
  auto source_address = connection.connectionInfoProvider().directRemoteAddress();
  auto destination_address = connection.connectionInfoProvider().directLocalAddress();

  Buffer::OwnedImpl packet = createPacket(buffer.linearize(buffer.length()), buffer.length(),
                                          source_address, destination_address);

  // Write packet to PCAP file
  PcapFileManager::getInstance().writeToPcap(
      static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());

  return true;
}

bool Analyzer::analyzeResponse(const Buffer::Instance& data, const Http::ResponseHeaderMap* headers,
                               const Http::ResponseTrailerMap* trailers,
                               const Network::Connection& connection) {

  Buffer::OwnedImpl buffer;
  if (headers) {
    std::string s = serializeResponseHeaders(*headers);
    buffer.add(s);
  }
  if (data.length() > 0) {
    buffer.add(data);
  }
  if (trailers) {
    std::string s = serializeResponseTrailers(*trailers);
    buffer.add(s);
  }

  // Get connection details
  auto source_address = connection.connectionInfoProvider().directLocalAddress();
  auto destination_address = connection.connectionInfoProvider().directRemoteAddress();

  Buffer::OwnedImpl packet = createPacket(buffer.linearize(buffer.length()), buffer.length(),
                                          source_address, destination_address);

  // Write packet to PCAP file
  PcapFileManager::getInstance().writeToPcap(
      static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());

  return true;
}

} // namespace Http
} // namespace Envoy

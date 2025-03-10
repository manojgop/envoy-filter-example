#include "snort_http.h"
#include "pcap_file_manager.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/http/codes.h"
#include "absl/status/statusor.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

namespace Envoy {
namespace Http {

// Snort Http Filter Config
SnortHttpFilterConfig::SnortHttpFilterConfig(const snort::SnortHttpConfig& proto_config,
                                             Stats::Scope& scope)
    : stat_prefix_(proto_config.stat_prefix()),
      stats_(generateStats(proto_config.stat_prefix(), scope)), action_(proto_config.action()),
      remote_ip_(getRemoteIP(proto_config)) {}

SnortHttpStats SnortHttpFilterConfig::generateStats(const std::string& prefix,
                                                    Stats::Scope& scope) {
  const std::string final_prefix = Envoy::statPrefixJoin(prefix, "snort.http.");
  return {ALL_SNORT_HTTP_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
}

std::unique_ptr<CidrRange>
SnortHttpFilterConfig::getRemoteIP(const snort::SnortHttpConfig& proto_config) {
  if (proto_config.has_remote_ip()) {
    absl::StatusOr<CidrRange> remote_ip_or_error = CidrRange::create(proto_config.remote_ip());
    if (!remote_ip_or_error.ok()) {
      return nullptr;
    }
    return std::make_unique<CidrRange>(std::move(remote_ip_or_error.value()));
  }
  return nullptr;
}

// Snort Http Filter
SnortHttpFilter::SnortHttpFilter(SnortHttpFilterConfigSharedPtr config) : config_(config) {}

FilterHeadersStatus SnortHttpFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                   bool end_stream) {
  ENVOY_LOG(trace, "snort http: decodeHeaders Host value {}, end_stream : {}",
            headers.getHostValue(), end_stream);

  request_headers_ = &headers;
  if (end_stream) {
    analyzeRequest();
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

FilterDataStatus SnortHttpFilter::decodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "snort http: decodeData got {} bytes", data.length());

  // Move data to internal buffer
  // This will also drain the data to ensure decodeData() gets new data on next call
  buffered_request_data_.move(data);

  if (end_stream) {
    analyzeRequest();
    // Move the buffered data back to data and call continue.
    // This will pass the buffered data to the next filter in the filter chain.
    data.move(buffered_request_data_);
    return Http::FilterDataStatus::Continue;
  }
  return Http::FilterDataStatus::StopIterationAndBuffer;
}

FilterTrailersStatus SnortHttpFilter::decodeTrailers(Http::RequestTrailerMap& trailers) {
  request_trailers_ = &trailers;
  analyzeRequest();
  return Http::FilterTrailersStatus::Continue;
}

void SnortHttpFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

FilterHeadersStatus SnortHttpFilter::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                   bool end_stream) {
  ENVOY_LOG(trace, "snort http: encodeHeaders status {}, end_stream: {}", headers.getStatusValue(),
            end_stream);
  response_headers_ = &headers;
  if (end_stream) {
    analyzeResponse();
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

FilterDataStatus SnortHttpFilter::encodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "snort http: encodeData got {} bytes, end_stream: {}", data.length(),
            end_stream);
  // Move data to internal buffer
  // This will also drain the data to ensure encodeData() gets new data on next call
  buffered_response_data_.move(data);

  if (end_stream) {
    analyzeResponse();
    ENVOY_LOG(trace, "snort http: encodeData Got end stream");
    // Move the buffered data back to data and call continue.
    // This will pass the buffered data to the next filter in the filter chain.
    data.move(buffered_response_data_);
    ENVOY_LOG(trace, "snort http: encodeData Got end stream #2");
    return Http::FilterDataStatus::Continue;
  }

  return Http::FilterDataStatus::StopIterationAndBuffer;
}

FilterTrailersStatus SnortHttpFilter::encodeTrailers(Http::ResponseTrailerMap& trailers) {
  response_trailers_ = &trailers;
  analyzeResponse();
  return Http::FilterTrailersStatus::Continue;
}

void SnortHttpFilter::setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

void SnortHttpFilter::analyzeRequest() {
  config_->stats().total_request_.inc();
  bool result = performRequestAnalysis();
  if (result) {
    config_->stats().allowed_request_.inc();
  } else {
    config_->stats().denied_request_.inc();
    decoder_callbacks_->sendLocalReply(
        Http::Code::Forbidden, "Request denied by snort http filter\n", nullptr, absl::nullopt, "");
  }
}

void SnortHttpFilter::analyzeResponse() {
  config_->stats().total_response_.inc();
  bool result = performResponseAnalysis();
  if (result) {
    config_->stats().allowed_response_.inc();
  } else {
    config_->stats().denied_response_.inc();
    encoder_callbacks_->sendLocalReply(Http::Code::Forbidden, "Denied by snort http filter\n",
                                       nullptr, absl::nullopt, "");
  }
}

bool SnortHttpFilter::performRequestAnalysis() {
  Buffer::OwnedImpl buffer;
  if (request_headers_) {
    std::string s = serializeRequestHeaders(*request_headers_);
    buffer.add(s);
  }
  if (buffered_request_data_.length() > 0) {
    buffer.add(buffered_request_data_);
  }
  /*if (request_trailers_) {
    std::string s = serializeRequestTrailes(*request_trailers_);
    buffer.add(s);
  }*/

  // Get connection details
  auto& connection = decoder_callbacks_->connection().ref();
  auto source_address = connection.connectionInfoProvider().directRemoteAddress();
  auto destination_address = connection.connectionInfoProvider().directLocalAddress();

  Buffer::OwnedImpl packet = createPacket(buffer, source_address, destination_address);

  // Write packet to PCAP file
  PcapFileManager::getInstance().writeToPcap(
      static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());

  // Allow/deny traffic
  bool ret = checkIP(source_address->ip()->addressAsString());

  return ret;
}

bool SnortHttpFilter::performResponseAnalysis() {
  Buffer::OwnedImpl buffer;
  if (response_headers_) {
    std::string s = serializeResponseHeaders(*response_headers_);
    buffer.add(s);
  }
  if (buffered_response_data_.length() > 0) {
    buffer.add(buffered_response_data_);
  }

  // Get connection details
  auto& connection = encoder_callbacks_->connection().ref();
  auto source_address = connection.connectionInfoProvider().directLocalAddress();
  auto destination_address = connection.connectionInfoProvider().directRemoteAddress();

  Buffer::OwnedImpl packet = createPacket(buffer, source_address, destination_address);

  // Write packet to PCAP file
  PcapFileManager::getInstance().writeToPcap(
      static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());

  // Allow/deny traffic
  // bool ret = checkIP(destination_address->ip()->addressAsString());

  return true;
}

bool SnortHttpFilter::checkIP(const std::string& ip) {
  bool match = true;
  if (config_->remoteIP() != nullptr) {
    const std::string& config_remote_ip = config_->remoteIP()->ip()->addressAsString();
    ENVOY_LOG(trace, "snort http: config remote IP : {}, dowonstream remote IP : {}",
              config_remote_ip, ip);
    if (config_remote_ip != ip) {
      match = false;
    }
  }
  if ((match && config_->action() == snort::SnortHttpConfig_Action_DENY) ||
      (!match && config_->action() == snort::SnortHttpConfig_Action_ALLOW)) {
    ENVOY_LOG(trace, "snort http: Denied connection from/to downstream remote IP : {}", ip);
    match = false;
  }
  return match;
}

std::string SnortHttpFilter::serializeRequestHeaders(const Http::RequestHeaderMap& headers) {
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

std::string SnortHttpFilter::serializeResponseHeaders(const Http::ResponseHeaderMap& headers) {
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

std::string SnortHttpFilter::serializeRequestTrailers(const Http::RequestTrailerMap& trailers) {
  return serializeHeaders(trailers);
}

std::string SnortHttpFilter::serializeResponseTrailers(const Http::ResponseTrailerMap& trailers) {
  return serializeHeaders(trailers);
}

std::string SnortHttpFilter::serializeHeaders(const Http::HeaderMap& headers) {
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
SnortHttpFilter::createPacket(Buffer::Instance& data,
                              const Network::Address::InstanceConstSharedPtr& source_address,
                              const Network::Address::InstanceConstSharedPtr& destination_address) {
  // Payload
  uint8_t* payload = static_cast<uint8_t*>(data.linearize(data.length()));
  size_t payload_length = data.length();

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
  ip_hdr.ip_v = 4;     // IPv4
  ip_hdr.ip_hl = 5;    // Header length
  ip_hdr.ip_ttl = 255; // Time to live
  ip_hdr.ip_id = htons(0x1234);
  ip_hdr.ip_p = IPPROTO_TCP; // Protocol
  ip_hdr.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + payload_length);
  ip_hdr.ip_src.s_addr = inet_addr(source_address->ip()->addressAsString().c_str());
  ip_hdr.ip_dst.s_addr = inet_addr(destination_address->ip()->addressAsString().c_str());
  // ip_hdr.ip_sum = checksum(reinterpret_cast<uint16_t *>(&ip_hdr), sizeof(struct ip) / 2);

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

  /*uint8_t pseudo_header[12];
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

  delete[] tcp_segment;*/

  // Create packet with header and payload
  Buffer::OwnedImpl packet;
  packet.add(&eth_header, sizeof(eth_header));
  packet.add(&ip_hdr, sizeof(ip_hdr));
  packet.add(&tcp_hdr, sizeof(tcp_hdr));
  packet.add(payload, payload_length);

  return packet;
}

// Function to calculate checksum
uint16_t SnortHttpFilter::checksum(const uint16_t* buf, size_t nwords) {
  uint64_t sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

} // namespace Http
} // namespace Envoy

#include "snort.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"
#include "source/common/common/assert.h"
#include "absl/status/statusor.h"
#include "source/common/buffer/buffer_impl.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>


namespace Envoy {
namespace Filter {

// Snort Filter Config
SnortFilterConfig::SnortFilterConfig(
    const snort::SnortConfig& proto_config, Stats::Scope& scope)
    : stat_prefix_(proto_config.stat_prefix()),
      stats_(generateStats(proto_config.stat_prefix(),scope)),
      action_(proto_config.action()),
      remote_ip_(getRemoteIP(proto_config)) {

}

SnortStats SnortFilterConfig::generateStats(const std::string& prefix, Stats::Scope& scope) {
  const std::string final_prefix = Envoy::statPrefixJoin(prefix, "snort.");
  return {ALL_SNORT_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
}

std::unique_ptr<CidrRange> SnortFilterConfig::getRemoteIP(const snort::SnortConfig& proto_config) {
  if(proto_config.has_remote_ip()){
    absl::StatusOr<CidrRange> remote_ip_or_error = CidrRange::create(proto_config.remote_ip());
    if(!remote_ip_or_error.ok()) {
      return nullptr;
    }
    return std::make_unique<CidrRange>(std::move(remote_ip_or_error.value()));
  }
  return nullptr;
}

// Analyze

Analyzer::Analyzer(SnortFilterConfigSharedPtr config, Network::Connection &connection,
  std::chrono::milliseconds tick_interval, uint64_t max_chunk_length,
  std::function<void(Buffer::Instance&, bool)> next_chunk_cb)
: config_(config), connection_(connection),
  timer_(connection.dispatcher().createTimer([this] { onTimerTick(); })),
  tick_interval_(tick_interval), max_chunk_length_(max_chunk_length), next_chunk_cb_(next_chunk_cb) {
}

void Analyzer::analyze(Buffer::Instance& data, bool end_stream) {

  Buffer::OwnedImpl packet = createPacket(data);
  // Write packet to PCAP file
  pcap_file_manager.writePacket(
    static_cast<const uint8_t*>(packet.linearize(packet.length())), packet.length());

  config_->stats().total_.inc();
  const std::string &connection_remote_ip
    = connection_.connectionInfoProvider().remoteAddress()->ip()->addressAsString();
  bool match = true;
  if(config_->remoteIP() != nullptr) {
    const std::string &config_remote_ip = config_->remoteIP()->ip()->addressAsString();
    ENVOY_CONN_LOG(trace, "snort: config remote IP : {}, connection remote IP : {}",
      connection_, config_remote_ip, connection_remote_ip);
    if(config_remote_ip != connection_remote_ip) {
       match = false;
    }
  }

  if((match && config_->action() == snort::SnortConfig_Action_DENY) ||
      (!match && config_->action() == snort::SnortConfig_Action_ALLOW)) {
    ENVOY_CONN_LOG(trace, "snort: Denied connection from remote IP : {}",
      connection_, connection_remote_ip);
    config_->stats().denied_.inc();
    connection_.close(Network::ConnectionCloseType::NoFlush, "snort_deny_close");
    if (timer_->enabled()) {
      timer_->disableTimer();
    }
    return;
  }
  ENVOY_CONN_LOG(trace, "snort: Allowed connection from remote IP : {}",
    connection_, connection_remote_ip);

  config_->stats().allowed_.inc();

  // Move to internal buffer
  buffer_.move(data);
  end_stream_ |= end_stream;
  if (!timer_->enabled()) {
    timer_->enableTimer(tick_interval_);
  }
}

Buffer::OwnedImpl Analyzer::createPacket(Buffer::Instance& data) {
  // Payload
  uint8_t* payload = static_cast<uint8_t*>(data.linearize(data.length()));
  size_t payload_length = data.length();

  // Get connection details
  auto source_address = connection_.streamInfo().downstreamAddressProvider().directRemoteAddress();
  auto destination_address = connection_.streamInfo().downstreamAddressProvider().localAddress();

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
  ip_hdr.ip_v = 4; // IPv4
  ip_hdr.ip_hl = 5; // Header length
  ip_hdr.ip_ttl = 255; // Time to live
  ip_hdr.ip_id = 0x1234;
  ip_hdr.ip_p = IPPROTO_TCP; // Protocol
  ip_hdr.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + payload_length);
  ip_hdr.ip_src.s_addr = inet_addr(source_address->ip()->addressAsString().c_str());
  ip_hdr.ip_dst.s_addr = inet_addr(destination_address->ip()->addressAsString().c_str());

  // Construct TCP header
  struct tcphdr tcp_hdr;
  memset(&tcp_hdr, 0, sizeof(tcp_hdr));
  tcp_hdr.th_off = 5; // Data offset
  tcp_hdr.th_flags = TH_ACK;//TH_SYN; // Flags
  tcp_hdr.th_win = htons(8192); // Window size
  tcp_hdr.th_sport = htons(source_address->ip()->port());
  tcp_hdr.th_dport = htons(destination_address->ip()->port());

  static int cnt = 1;
  tcp_hdr.th_seq = cnt++;
  tcp_hdr.th_ack = cnt - 1;
  tcp_hdr.seq = 0;
  tcp_hdr.ack_seq = 0;

  // Create packet with header and payload
  Buffer::OwnedImpl packet;
  packet.add(&eth_header, sizeof(eth_header));
  packet.add(&ip_hdr, sizeof(ip_hdr));
  packet.add(&tcp_hdr, sizeof(tcp_hdr));
  packet.add(payload, payload_length);

  return packet;
}

void Analyzer::reset() {
  ENVOY_CONN_LOG(trace, "Analyzer: Reset",connection_);
  timer_->disableTimer();
}

void Analyzer::onTimerTick() {
  Buffer::OwnedImpl next_chunk{};
  if (0 < buffer_.length()) {
    auto chunk_length = max_chunk_length_ < buffer_.length() ? max_chunk_length_ : buffer_.length();
    next_chunk.move(buffer_, chunk_length);
  }
  bool end_stream = end_stream_ && 0 == buffer_.length();
  if (0 < buffer_.length()) {
    timer_->enableTimer(tick_interval_);
  }
  next_chunk_cb_(next_chunk, end_stream);
}

// Pcap File writer
PcapFileManager::PcapFileManager() {
  ENVOY_LOG(trace, "Create pcap file");
  pcap_ = pcap_open_dead(DLT_EN10MB, 65535);
  dumper_ = pcap_dump_open(pcap_, "output.pcap");
  if (!dumper_) {
      throw std::runtime_error("Failed to open PCAP file");
  }
}

PcapFileManager::~PcapFileManager() {
  close();
}

void PcapFileManager::writePacket(const uint8_t* data, size_t length) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (dumper_) {
      struct pcap_pkthdr header;
      header.ts.tv_sec = time(nullptr);
      header.ts.tv_usec = 0;
      header.caplen = length;
      header.len = length;
      pcap_dump(reinterpret_cast<u_char*>(dumper_), &header, data);
      pcap_dump_flush(dumper_);
  }
}

void PcapFileManager::close() {
  std::lock_guard<std::mutex> lock(mutex_);
  ENVOY_LOG(trace, "Save pcap file");
  if (dumper_) {
      pcap_dump_close(dumper_);
      dumper_ = nullptr;
  }
  if (pcap_) {
      pcap_close(pcap_);
      pcap_ = nullptr;
  }
}


// Snort Filter
Snort::Snort(SnortFilterConfigSharedPtr config)
    : config_(config) {
  tick_interval_ = std::chrono::milliseconds(1);
  max_chunk_length_= 256;
}

void Snort::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
  read_callbacks_->connection().addConnectionCallbacks(*this);

  read_analyzer_ = std::make_unique<Analyzer>(
      config_, read_callbacks_->connection(), tick_interval_, max_chunk_length_,
      [this](Buffer::Instance& data, bool end_stream) {
        read_callbacks_->injectReadDataToFilterChain(data, end_stream);
      });
}

Network::FilterStatus Snort::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(trace, "snort: onData got {} bytes", read_callbacks_->connection(), data.length());
  ENVOY_CONN_LOG(trace,
    "snort: connectionInfoProvider remote address : {},\
    downstreamAddressProvider remote address : {},\
    downstreamAddressProvider direct remote address : {},\
    downstreamAddressProvider local address : {},\
    downstreamAddressProvider direct local address : {}",
    read_callbacks_->connection(),
    read_callbacks_->connection().connectionInfoProvider().remoteAddress()->asString(),
    read_callbacks_->connection().streamInfo().downstreamAddressProvider().remoteAddress()->asString(),
    read_callbacks_->connection().streamInfo().downstreamAddressProvider().directRemoteAddress()->asString(),
    read_callbacks_->connection().streamInfo().downstreamAddressProvider().localAddress()->asString(),
    read_callbacks_->connection().streamInfo().downstreamAddressProvider().directLocalAddress()->asString()
  );

  read_analyzer_->analyze(data, end_stream);

  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Snort::onWrite(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "snort: onWrite got {} bytes", data.length());

  write_analyzer_->analyze(data, end_stream);

  return Network::FilterStatus::StopIteration;

}

void Snort::initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) {
  write_callbacks_ = &callbacks;
  write_callbacks_->connection().addConnectionCallbacks(*this);

  write_analyzer_ = std::make_unique<Analyzer>(
      config_, write_callbacks_->connection(), tick_interval_, max_chunk_length_,
      [this](Buffer::Instance& data, bool end_stream) {
        write_callbacks_->injectWriteDataToFilterChain(data, end_stream);
      });
}

void Snort::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    read_analyzer_->reset();
  }
}

} // namespace Filter
} // namespace Envoy

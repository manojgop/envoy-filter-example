#include "snort.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"
#include "source/common/common/assert.h"
#include "absl/status/statusor.h"


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
void Analyzer::analyze(Buffer::Instance& data, bool end_stream) {
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

  buffer_.move(data);
  end_stream_ |= end_stream;
  if (!timer_->enabled()) {
    timer_->enableTimer(tick_interval_);
  }
}

void Analyzer::reset() {
  ENVOY_CONN_LOG(trace, "snort: Reset",connection_);
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
  ENVOY_CONN_LOG(trace, "snort: got {} bytes", read_callbacks_->connection(), data.length());
  ENVOY_CONN_LOG(trace,
    "snort: connectionInfoProvider remote address : {},\
    downstreamAddressProvider remote address : {},\
    downstreamAddressProvider direct remote address : {}",
    read_callbacks_->connection(),
    read_callbacks_->connection().connectionInfoProvider().remoteAddress()->asString(),
    read_callbacks_->connection().streamInfo().downstreamAddressProvider().remoteAddress()->asString(),
    read_callbacks_->connection().streamInfo().downstreamAddressProvider().directRemoteAddress()->asString()
  );

  read_analyzer_->analyze(data, end_stream);

  return Network::FilterStatus::StopIteration;
}

void Snort::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    read_analyzer_->reset();
  }
}

} // namespace Filter
} // namespace Envoy

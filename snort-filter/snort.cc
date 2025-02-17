#include "snort.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"
#include "source/common/common/assert.h"
#include "absl/status/statusor.h"


namespace Envoy {
namespace Filter {

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

Snort::Snort(SnortFilterConfigSharedPtr config)
    : config_(config) {}


Network::FilterStatus Snort::onData(Buffer::Instance& data, bool) {
  ENVOY_CONN_LOG(trace, "snort: got {} bytes", read_callbacks_->connection(), data.length());
  config_->stats().total_.inc();
  const std::string &connection_remote_ip
    = read_callbacks_->connection().connectionInfoProvider().remoteAddress()->ip()->addressAsString();
  bool match = true;
  if(config_->remoteIP() != nullptr) {
    const std::string &config_remote_ip = config_->remoteIP()->ip()->addressAsString();
    ENVOY_CONN_LOG(trace, "snort: config remote IP : {}, connection remote IP : {}",
      read_callbacks_->connection(), config_remote_ip, connection_remote_ip);
    if(config_remote_ip != connection_remote_ip) {
       match = false;
    }
  }

  if((match && config_->action() == snort::SnortConfig_Action_DENY) ||
      (!match && config_->action() == snort::SnortConfig_Action_ALLOW)) {
    ENVOY_CONN_LOG(trace, "snort: Denied connection from remote IP : {}",
        read_callbacks_->connection(), connection_remote_ip);
    config_->stats().denied_.inc();
    read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush, "snort_deny_close");
    return Network::FilterStatus::StopIteration;
  }

  ENVOY_CONN_LOG(trace, "snort: Allowed connection from remote IP : {}",
      read_callbacks_->connection(), connection_remote_ip);

  config_->stats().allowed_.inc();
  return  Network::FilterStatus::Continue;
}

} // namespace Filter
} // namespace Envoy

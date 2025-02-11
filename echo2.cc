#include "echo2.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"

#include "source/common/common/assert.h"

namespace Envoy {
namespace Filter {

Echo2FilterConfig::Echo2FilterConfig(
    const echoconfig::EchoConfig& proto_config, Stats::Scope& scope)
    : stat_prefix_(proto_config.stat_prefix()),
      stats_(generateStats(proto_config.stat_prefix(),scope)) {}

Echo2Stats Echo2FilterConfig::generateStats(const std::string& prefix, Stats::Scope& scope) {
  const std::string final_prefix = Envoy::statPrefixJoin(prefix, "echo2.");
  return {ALL_ECHO2_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
}

Echo2::Echo2(Echo2FilterConfigSharedPtr config)
    : config_(config) {}


Network::FilterStatus Echo2::onData(Buffer::Instance& data, bool) {
  ENVOY_CONN_LOG(trace, "echo: got {} bytes", read_callbacks_->connection(), data.length());
  config_->stats().received_.inc();
  read_callbacks_->connection().write(data, false);
  return Network::FilterStatus::StopIteration;
}

} // namespace Filter
} // namespace Envoy

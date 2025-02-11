#pragma once

#include "echo_config.pb.h"
#include "envoy/network/filter.h"
#include "envoy/stats/stats_macros.h"
#include "source/common/common/logger.h"

namespace Envoy {
namespace Filter {

/**
 * All echo2 stats. @see stats_macros.h
 */
#define ALL_ECHO2_STATS(COUNTER) COUNTER(received)

/**
 * Struct definition for echo2 stats. @see stats_macros.h
 */
struct Echo2Stats {
  ALL_ECHO2_STATS(GENERATE_COUNTER_STRUCT)
};

class Echo2FilterConfig {
public:
  Echo2FilterConfig(const echoconfig::EchoConfig& proto_config, Stats::Scope& scope);

  const std::string& statPrefix() const { return stat_prefix_; }
  Echo2Stats& stats() { return stats_; }

private:
  const std::string stat_prefix_;
  Echo2Stats stats_;
  static Echo2Stats generateStats(const std::string& prefix, Stats::Scope& scope);
};

using Echo2FilterConfigSharedPtr = std::shared_ptr<Echo2FilterConfig>;

/**
 * Implementation of a basic echo filter.
 */
class Echo2 : public Network::ReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Echo2(Echo2FilterConfigSharedPtr);

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override { return Network::FilterStatus::Continue; }
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
  }

private:
  const Echo2FilterConfigSharedPtr config_;
  Network::ReadFilterCallbacks* read_callbacks_{};
};

} // namespace Filter
} // namespace Envoy

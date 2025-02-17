#pragma once


#include "envoy/network/filter.h"
#include "snort-filter/snort.pb.h"
#include "envoy/stats/stats_macros.h"
#include "source/common/common/logger.h"
#include "source/common/network/cidr_range.h"

namespace Envoy {
namespace Filter {

/**
 * All snort stats. @see stats_macros.h
 */
#define ALL_SNORT_STATS(COUNTER) \
  COUNTER(allowed)               \
  COUNTER(denied)                \
  COUNTER(total)                 \


/**
 * Struct definition for snort stats. @see stats_macros.h
 */
struct SnortStats {
  ALL_SNORT_STATS(GENERATE_COUNTER_STRUCT)
};

using CidrRange = Envoy::Network::Address::CidrRange;

class SnortFilterConfig {
public:
  SnortFilterConfig(const snort::SnortConfig& proto_config, Stats::Scope& scope);

  const std::string& statPrefix() const { return stat_prefix_; }
  SnortStats& stats() { return stats_; }
  const snort::SnortConfig_Action& action() { return  action_ ;}
  const std::unique_ptr<const CidrRange>& remoteIP() { return remote_ip_ ;}

private:
  const std::string stat_prefix_;
  SnortStats stats_;
  const snort::SnortConfig_Action action_;
  const std::unique_ptr<const CidrRange> remote_ip_;
  static SnortStats generateStats(const std::string& prefix, Stats::Scope& scope);
  static std::unique_ptr<CidrRange> getRemoteIP(const snort::SnortConfig& proto_config);
};

using SnortFilterConfigSharedPtr = std::shared_ptr<SnortFilterConfig>;

/**
 * Implementation of a basic snort filter.
 */
class Snort : public Network::ReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Snort(SnortFilterConfigSharedPtr);

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override { return Network::FilterStatus::Continue; }
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
  }

private:
  const SnortFilterConfigSharedPtr config_;
  Network::ReadFilterCallbacks* read_callbacks_{};
};

} // namespace Filter
} // namespace Envoy

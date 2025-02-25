#pragma once

#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "snort-filter/snort.pb.h"
#include "envoy/stats/stats_macros.h"
#include "source/common/common/logger.h"
#include "source/common/network/cidr_range.h"
#include "source/common/buffer/buffer_impl.h"

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
//using Connection = Envoy::Network::Connection;
using ConnectionSharedPtr = std::shared_ptr<Envoy::Network::Connection>;

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
 * Traffic analayzer using snort.
 * emits a next chunk of the original request/response data on timer tick.
 */
class Analyzer : public Logger::Loggable<Logger::Id::filter> {
public:
Analyzer(SnortFilterConfigSharedPtr config, Network::Connection &connection,
            std::chrono::milliseconds tick_interval, uint64_t max_chunk_length,
            std::function<void(Buffer::Instance&, bool)> next_chunk_cb)
      : config_(config), connection_(connection),
        timer_(connection.dispatcher().createTimer([this] { onTimerTick(); })),
        tick_interval_(tick_interval),
        max_chunk_length_(max_chunk_length), next_chunk_cb_(next_chunk_cb) {}

  /**
   * Analyze given given request/response data.
   */
  void analyze(Buffer::Instance& data, bool end_stream);
  /**
   * Cancel any scheduled activities (on connection close).
   */
  void reset();

private:
  void onTimerTick();

  Buffer::OwnedImpl buffer_{};
  bool end_stream_{};

  const SnortFilterConfigSharedPtr config_;
  Network::Connection &connection_;
  const Event::TimerPtr timer_;
  const std::chrono::milliseconds tick_interval_;
  const uint64_t max_chunk_length_;
  const std::function<void(Buffer::Instance&, bool)> next_chunk_cb_;
};


/**
 * Implementation of a basic snort filter.
 */
class Snort : public Network::ReadFilter, Network::ConnectionCallbacks,
              Logger::Loggable<Logger::Id::filter> {
public:
  Snort(SnortFilterConfigSharedPtr);

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override { return Network::FilterStatus::Continue; }
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;

  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

private:
  const SnortFilterConfigSharedPtr config_;
  std::chrono::milliseconds tick_interval_;
  uint64_t max_chunk_length_;
  Network::ReadFilterCallbacks* read_callbacks_{};
  std::unique_ptr<Analyzer> read_analyzer_;
};

} // namespace Filter
} // namespace Envoy

#pragma once

#include "analyzer.h"
#include "envoy/buffer/buffer.h"
#include "envoy/http/filter.h"
#include "envoy/stats/stats_macros.h"
#include "source/common/common/logger.h"
#include "source/common/network/cidr_range.h"
#include "snort-http-filter/snorthttp.pb.h"

#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Http {

/**
 * All snort http stats. @see stats_macros.h
 */
#define ALL_SNORT_HTTP_STATS(COUNTER)                                                              \
  COUNTER(allowed_request)                                                                         \
  COUNTER(denied_request)                                                                          \
  COUNTER(total_request)                                                                           \
  COUNTER(allowed_response)                                                                        \
  COUNTER(denied_response)                                                                         \
  COUNTER(total_response)

/**
 * Struct definition for snort stats. @see stats_macros.h
 */
struct SnortHttpStats {
  ALL_SNORT_HTTP_STATS(GENERATE_COUNTER_STRUCT)
};

using CidrRange = Envoy::Network::Address::CidrRange;

class SnortHttpFilterConfig {
public:
  SnortHttpFilterConfig(const snort::SnortHttpConfig& proto_config, Stats::Scope& scope);

  const std::string& statPrefix() const { return stat_prefix_; }
  SnortHttpStats& stats() { return stats_; }
  const snort::SnortHttpConfig_Action& action() { return action_; }
  const std::unique_ptr<const CidrRange>& remoteIP() { return remote_ip_; }

private:
  const std::string stat_prefix_;
  SnortHttpStats stats_;
  const snort::SnortHttpConfig_Action action_;
  const std::unique_ptr<const CidrRange> remote_ip_;
  static SnortHttpStats generateStats(const std::string& prefix, Stats::Scope& scope);
  static std::unique_ptr<CidrRange> getRemoteIP(const snort::SnortHttpConfig& proto_config);
};

using SnortHttpFilterConfigSharedPtr = std::shared_ptr<SnortHttpFilterConfig>;

class SnortHttpFilter : public Http::PassThroughFilter, Logger::Loggable<Logger::Id::filter> {
public:
  SnortHttpFilter(SnortHttpFilterConfigSharedPtr);

  FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) override;
  FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

  FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers, bool end_stream) override;
  FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) override;
  FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap& trailers) override;
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override;

private:
  const SnortHttpFilterConfigSharedPtr config_;
  StreamDecoderFilterCallbacks* decoder_callbacks_{};
  StreamEncoderFilterCallbacks* encoder_callbacks_{};

  std::unique_ptr<RequestAnalyzer> request_analyzer_;
  std::unique_ptr<ResponseAnalyzer> response_analyzer_;

  Http::RequestHeaderMap* request_headers_ = nullptr;
  Buffer::OwnedImpl buffered_request_data_;
  Http::RequestTrailerMap* request_trailers_ = nullptr;

  Http::ResponseHeaderMap* response_headers_ = nullptr;
  Buffer::OwnedImpl buffered_response_data_;
  Http::ResponseTrailerMap* response_trailers_ = nullptr;

  uint64_t processed_request_length_ = 0;
  uint64_t processed_response_length_ = 0;
  const size_t kThreshold = 1024;

  void analyzeRequest(bool end_stream);
  void analyzeResponse(bool end_stream);

  bool processData(const Envoy::Buffer::Instance& buffer, uint64_t& processed_length,
                   uint64_t threshold, bool end_stream, bool is_request);
  bool processBufferedData(const Envoy::Buffer::Instance& buffer, size_t start_offset,
                           size_t length, bool is_request);
  bool processRequest(const uint8_t* data, size_t size);
  bool processResponse(const uint8_t* data, size_t size);
  bool isAllowedIP(const std::string& ip);
};

} // namespace Http
} // namespace Envoy

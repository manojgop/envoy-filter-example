#pragma once

#include "analyzer.h"
#include "envoy/buffer/buffer.h"
#include "envoy/http/filter.h"
#include "envoy/stats/stats_macros.h"
#include "source/common/common/logger.h"
#include "snort-http-filter/snorthttp.pb.h"

#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SnortHttp {

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

class SnortHttpFilterConfig {
public:
  SnortHttpFilterConfig(const envoy::filters::http::snort::SnortHttpConfig& proto_config,
                        Stats::Scope& scope);

  const std::string& statPrefix() const { return stat_prefix_; }
  SnortHttpStats& stats() { return stats_; }
  bool savePcapField() const { return save_pcap_; }
  bool analyseRequestField() const { return analyze_request_; }
  bool analyseResponseField() const { return analyze_response_; }

private:
  const std::string stat_prefix_;
  SnortHttpStats stats_;
  const bool save_pcap_;
  const bool analyze_request_;
  const bool analyze_response_;
  static SnortHttpStats generateStats(const std::string& prefix, Stats::Scope& scope);
};

using SnortHttpFilterConfigSharedPtr = std::shared_ptr<SnortHttpFilterConfig>;

class SnortHttpFilter : public Http::PassThroughFilter, Logger::Loggable<Logger::Id::filter> {
public:
  SnortHttpFilter(SnortHttpFilterConfigSharedPtr);

  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap& trailers) override;
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override;

private:
  const SnortHttpFilterConfigSharedPtr config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{};

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
};

} // namespace SnortHttp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

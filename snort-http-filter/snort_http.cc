#include "snort_http.h"

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
SnortHttpFilter::SnortHttpFilter(SnortHttpFilterConfigSharedPtr config) : config_(config) {

  analyzer_ = std::make_unique<Analyzer>();
}

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
  bool analyze =
      analyzer_->analyzeRequest(buffered_request_data_, request_headers_, request_trailers_,
                                decoder_callbacks_->connection().ref());

  // Check if remote IP is allowed based on filter configuration.
  // Note: This check is temporary. Added to test filter configuration. Will be removed later.
  auto& connection = decoder_callbacks_->connection().ref();
  auto source_address = connection.connectionInfoProvider().directRemoteAddress();
  auto ip = source_address->ip()->addressAsString();
  bool allow = isAllowedIP(ip);

  if (analyze && allow) {
    config_->stats().allowed_request_.inc();
  } else {
    config_->stats().denied_request_.inc();
    decoder_callbacks_->sendLocalReply(
        Http::Code::Forbidden, "Request denied by snort http filter\n", nullptr, absl::nullopt, "");
  }
}

void SnortHttpFilter::analyzeResponse() {
  config_->stats().total_response_.inc();
  bool analyze =
      analyzer_->analyzeResponse(buffered_response_data_, response_headers_, response_trailers_,
                                 encoder_callbacks_->connection().ref());
  if (analyze) {
    config_->stats().allowed_response_.inc();
  } else {
    config_->stats().denied_response_.inc();
    encoder_callbacks_->sendLocalReply(Http::Code::Forbidden, "Denied by snort http filter\n",
                                       nullptr, absl::nullopt, "");
  }
}

bool SnortHttpFilter::isAllowedIP(const std::string& ip) {
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

} // namespace Http
} // namespace Envoy

#include "snort_http.h"
#include "source/common/buffer/buffer_impl.h"

namespace Envoy {
namespace Http {

// Snort Http Filter Config
SnortHttpFilterConfig::SnortHttpFilterConfig(const snort::SnortHttpConfig& proto_config,
                                             Stats::Scope& scope)
    : stat_prefix_(proto_config.stat_prefix()),
      stats_(generateStats(proto_config.stat_prefix(), scope)),
      save_pcap_(proto_config.save_pcap()), analyze_request_(getAnalyzeRequest(proto_config)),
      analyze_response_(proto_config.analyze_response()) {}

SnortHttpStats SnortHttpFilterConfig::generateStats(const std::string& prefix,
                                                    Stats::Scope& scope) {
  const std::string final_prefix = Envoy::statPrefixJoin(prefix, "snort.http.");
  return {ALL_SNORT_HTTP_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
}

bool SnortHttpFilterConfig::getAnalyzeRequest(const snort::SnortHttpConfig& proto_config) {
  // Analyze request is enabled by default if the field is not set
  if (!proto_config.has_analyze_request()) {
    return true;
  }
  return proto_config.analyze_request();
}

// Snort Http Filter
SnortHttpFilter::SnortHttpFilter(SnortHttpFilterConfigSharedPtr config) : config_(config) {
  ENVOY_LOG(trace, "snort http filter created");

  processed_request_length_ = 0;
  processed_response_length_ = 0;
  request_analyzer_ =
      std::make_unique<RequestAnalyzer>(config_->savePcapField(), config_->analyseRequestField());
  response_analyzer_ =
      std::make_unique<ResponseAnalyzer>(config_->savePcapField(), config_->analyseResponseField());
}

FilterHeadersStatus SnortHttpFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                   bool end_stream) {
  ENVOY_LOG(trace, "snort http: decodeHeaders Host value {}, end_stream : {}",
            headers.getHostValue(), end_stream);

  request_headers_ = &headers;

  if (end_stream) {
    analyzeRequest(end_stream);
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

FilterDataStatus SnortHttpFilter::decodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "snort http: decodeData got {} bytes", data.length());

  // Move data to internal buffer
  // This will drain the data to ensure decodeData() gets new data chunk on next call
  buffered_request_data_.move(data);

  analyzeRequest(end_stream);

  if (end_stream) {
    // Move all buffered data back to 'data' before continuing
    // Envoy filter manager will pass all buffered data to next filter in filter chain
    data.move(buffered_request_data_);
    return Envoy::Http::FilterDataStatus::Continue; // Resume filter chain processing
  }

  return Http::FilterDataStatus::StopIterationAndBuffer;
}

FilterTrailersStatus SnortHttpFilter::decodeTrailers(Http::RequestTrailerMap& trailers) {
  request_trailers_ = &trailers;
  analyzeRequest(true);
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
    analyzeResponse(end_stream);
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

FilterDataStatus SnortHttpFilter::encodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "snort http: encodeData got {} bytes, end_stream: {}", data.length(),
            end_stream);
  // Move data to internal buffer
  // This will drain the data to ensure encodeData() gets new data chunk on next call
  buffered_response_data_.move(data);

  analyzeResponse(end_stream);

  if (end_stream) {
    // Move all buffered data back to 'data' before continuing
    data.move(buffered_response_data_);
    return Envoy::Http::FilterDataStatus::Continue; // Resume filter chain processing
  }

  return Http::FilterDataStatus::StopIterationAndBuffer;
}

FilterTrailersStatus SnortHttpFilter::encodeTrailers(Http::ResponseTrailerMap& trailers) {
  response_trailers_ = &trailers;
  analyzeResponse(true);
  return Http::FilterTrailersStatus::Continue;
}

void SnortHttpFilter::setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

void SnortHttpFilter::analyzeRequest(bool end_stream) {
  bool result = true;
  // If there is buffered http body, process it.
  // This will process headers/trailers along with http body.
  if (buffered_request_data_.length() > 0) {
    result = processData(buffered_request_data_, processed_request_length_, kThreshold, end_stream,
                         true);
  }

  if (result) {
    // If http request does not have body and end of stream is reached process headers.
    // Process trailers if not processed yet.
    if ((end_stream && request_headers_) || request_trailers_) {
      result = processRequest(nullptr, 0);
    }
  }

  if (result) {
    if (end_stream) {
      config_->stats().total_request_.inc();
      config_->stats().allowed_request_.inc();
    }
  } else {
    config_->stats().total_request_.inc();
    config_->stats().denied_request_.inc();
    decoder_callbacks_->sendLocalReply(
        Http::Code::Forbidden, "Request denied by snort http filter\n", nullptr, absl::nullopt, "");
  }
}

void SnortHttpFilter::analyzeResponse(bool end_stream) {
  bool result = true;
  // If there is buffered http body process it.
  // This will process headers/trailers along with http body.
  if (buffered_response_data_.length() > 0) {
    result = processData(buffered_response_data_, processed_response_length_, kThreshold,
                         end_stream, false);
  }

  if (result) {
    // If http response does not have body and end of stream is reached process headers.
    // Process trailers if not processed yet.
    if ((end_stream && response_headers_) || response_trailers_) {
      result = processResponse(nullptr, 0);
    }
  }

  if (result) {
    if (end_stream) {
      config_->stats().total_response_.inc();
      config_->stats().allowed_response_.inc();
    }
  } else {
    config_->stats().total_response_.inc();
    config_->stats().denied_response_.inc();
    encoder_callbacks_->sendLocalReply(Http::Code::Forbidden,
                                       "Response denied by snort http filter\n", nullptr,
                                       absl::nullopt, "");
  }
}

bool SnortHttpFilter::processData(const Envoy::Buffer::Instance& buffer, uint64_t& processed_length,
                                  uint64_t threshold, bool end_stream, bool is_request) {

  bool result = true;
  // Process buffered data if it exceeds threshold
  while (buffer.length() - processed_length >= threshold) {
    size_t slice_length = threshold;
    result = processBufferedData(buffer, processed_length, slice_length, is_request);
    processed_length += slice_length; // Update processed length
    if (!result) {
      break;
    }
  }

  if (end_stream && result) {
    // Process remaining unprocessed data at end of stream
    if (buffer.length() > processed_length) {
      size_t remaining_size = buffer.length() - processed_length;
      result = processBufferedData(buffer, processed_length, remaining_size, is_request);
      processed_length += remaining_size;
    }
  }
  return result;
}

bool SnortHttpFilter::processBufferedData(const Envoy::Buffer::Instance& buffer,
                                          size_t start_offset, size_t length, bool is_request) {
  // Extract and process the required slice of buffered data
  const auto raw_slices = buffer.getRawSlices();
  size_t offset = 0;
  bool result = true;

  for (const auto& slice : raw_slices) {
    if (offset + slice.len_ <= start_offset) {
      offset += slice.len_; // Skip slices before start_offset
      continue;
    }

    size_t slice_start = std::max(start_offset - offset, static_cast<size_t>(0));
    size_t slice_end = std::min(slice_start + length, slice.len_);
    size_t process_len = slice_end - slice_start;

    if (process_len > 0) {
      const uint8_t* start_ptr = static_cast<const uint8_t*>(slice.mem_) + slice_start;
      if (is_request) {
        result = processRequest(start_ptr, process_len); // Process the chunk
      } else {
        result = processResponse(start_ptr, process_len); // Process the chunk
      }
      length -= process_len;
      if (length == 0)
        break;
    }
    offset += slice.len_;
    if (!result) {
      break;
    }
  }
  return result;
}

bool SnortHttpFilter::processRequest(const uint8_t* data, size_t size) {

  // Update ack for request. Ack all responses got so far.
  request_analyzer_->setAck(response_analyzer_->getSeq());

  bool allow = request_analyzer_->analyzeRequest(data, size, request_headers_, request_trailers_,
                                                 decoder_callbacks_->connection().ref());

  // Request header and trailer is processed. Set it to nullptr.
  request_headers_ = nullptr;
  request_trailers_ = nullptr;

  return allow;
}

bool SnortHttpFilter::processResponse(const uint8_t* data, size_t size) {

  // Update ack for response. Ack all requests got so far.
  response_analyzer_->setAck(request_analyzer_->getSeq());

  bool allow = response_analyzer_->analyzeResponse(
      data, size, response_headers_, response_trailers_, encoder_callbacks_->connection().ref());

  // Response header and trailer is processed. Set it to nullptr.
  response_headers_ = nullptr;
  response_trailers_ = nullptr;

  return allow;
}

} // namespace Http
} // namespace Envoy

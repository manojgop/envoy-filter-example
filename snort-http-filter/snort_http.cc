#include "snort_http.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/http/codes.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SnortHttp {

// Snort Http Filter Config
SnortHttpFilterConfig::SnortHttpFilterConfig(
    const envoy::filters::http::snort::SnortHttpConfig& proto_config, Stats::Scope& scope)
    : stat_prefix_(proto_config.stat_prefix()),
      stats_(generateStats(proto_config.stat_prefix(), scope)),
      save_pcap_(proto_config.save_pcap()), analyze_request_(proto_config.analyze_request()),
      analyze_response_(proto_config.analyze_response()),
      unix_socket_path_(getUnixSocketPath(proto_config)) {
  ENVOY_LOG(trace, "snort http config created");
}

SnortHttpStats SnortHttpFilterConfig::generateStats(const std::string& prefix,
                                                    Stats::Scope& scope) {
  const std::string final_prefix = Envoy::statPrefixJoin(prefix, "snort.http.");
  return {ALL_SNORT_HTTP_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
}

std::string SnortHttpFilterConfig::getUnixSocketPath(
    const envoy::filters::http::snort::SnortHttpConfig& proto_config) {
  std::string unix_socket_path;
  if (proto_config.has_unix_socket_path()) {
    unix_socket_path = proto_config.unix_socket_path();
  }
  if (unix_socket_path.empty()) {
    // Default socket path
    unix_socket_path = "/tmp/envoysnort.sock";
  }
  return unix_socket_path;
}

// Snort Http Filter
SnortHttpFilter::SnortHttpFilter(SnortHttpFilterConfigSharedPtr config) : config_(config) {
  ENVOY_LOG(trace, "snort http filter created");

  processed_request_length_ = 0;
  processed_response_length_ = 0;
  request_analyzer_ = std::make_unique<RequestAnalyzer>(
      config_->savePcapField(), config_->analyseRequestField(), config_->unixSocketPath());
  response_analyzer_ = std::make_unique<ResponseAnalyzer>(
      config_->savePcapField(), config_->analyseResponseField(), config_->unixSocketPath());
}

Http::FilterHeadersStatus SnortHttpFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                         bool end_stream) {
  ENVOY_LOG(trace, "snort http: decodeHeaders Host value {}, end_stream : {}",
            headers.getHostValue(), end_stream);

  if (headers.size() > 0) {
    std::string s = serializeRequestHeaders(headers);
    request_header_length_ += s.size();
    buffered_request_data_.add(s);
  }

  analyzeRequest(end_stream);

  if (end_stream) {
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus SnortHttpFilter::decodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "snort http: decodeData got {} bytes", data.length());

  // Move data to internal buffer
  // This will drain the data to ensure decodeData() gets new data chunk on next call
  buffered_request_data_.move(data);

  analyzeRequest(end_stream);

  if (end_stream) {
    // Remove headers from beginning buffered_request_data_
    buffered_request_data_.drain(request_header_length_);
    // Move all buffered data back to 'data' before continuing
    // Envoy filter manager will pass all buffered data to next filter in filter chain
    data.move(buffered_request_data_);
    processed_request_length_ = 0;                  // Reset processed length
    return Envoy::Http::FilterDataStatus::Continue; // Resume filter chain processing
  }

  return Http::FilterDataStatus::StopIterationAndBuffer;
}

Http::FilterTrailersStatus SnortHttpFilter::decodeTrailers(Http::RequestTrailerMap& trailers) {
  if (trailers.size() > 0) {
    std::string s = serializeRequestTrailers(trailers);
    buffered_request_data_.add(s);
  }
  analyzeRequest(true);
  return Http::FilterTrailersStatus::Continue;
}

void SnortHttpFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

Http::FilterHeadersStatus SnortHttpFilter::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                         bool end_stream) {
  ENVOY_LOG(trace, "snort http: encodeHeaders status {}, end_stream: {}", headers.getStatusValue(),
            end_stream);

  if (headers.size() > 0) {
    std::string s = serializeResponseHeaders(headers);
    response_header_length_ += s.size();
    buffered_response_data_.add(s);
  }

  analyzeResponse(end_stream);

  if (end_stream) {
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus SnortHttpFilter::encodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "snort http: encodeData got {} bytes, end_stream: {}", data.length(),
            end_stream);
  // Move data to internal buffer
  // This will drain the data to ensure encodeData() gets new data chunk on next call
  buffered_response_data_.move(data);

  analyzeResponse(end_stream);

  if (end_stream) {
    // Remove headers from beginning buffered_response_data_
    buffered_response_data_.drain(response_header_length_);
    // Move all buffered data back to 'data' before continuing
    data.move(buffered_response_data_);
    processed_response_length_ = 0;                 // Reset processed length
    return Envoy::Http::FilterDataStatus::Continue; // Resume filter chain processing
  }

  return Http::FilterDataStatus::StopIterationAndBuffer;
}

Http::FilterTrailersStatus SnortHttpFilter::encodeTrailers(Http::ResponseTrailerMap& trailers) {
  if (trailers.size() > 0) {
    std::string s = serializeResponseTrailers(trailers);
    buffered_response_data_.add(s);
  }
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
  const auto raw_slices = buffer.getRawSlices();
  size_t offset = 0;
  size_t remaining_length = length; // Track remaining length
  bool result = true;

  for (const auto& slice : raw_slices) {
    if (offset + slice.len_ <= start_offset) {
      offset += slice.len_; // Skip slices before start_offset
      continue;
    }

    size_t slice_start = (offset > start_offset) ? 0 : (start_offset - offset);
    size_t slice_end = std::min(slice_start + remaining_length, slice.len_);
    size_t process_len = slice_end - slice_start;

    if (process_len > 0) {
      const uint8_t* start_ptr = static_cast<const uint8_t*>(slice.mem_) + slice_start;
      if (is_request) {
        result = processRequest(start_ptr, process_len); // Process the chunk
      } else {
        result = processResponse(start_ptr, process_len); // Process the chunk
      }
      remaining_length -= process_len; // Decrement remaining length
      if (remaining_length == 0) {
        break; // Stop processing once the required length is processed
      }
    }
    offset += slice.len_;
    if (!result) {
      break; // Stop processing if an error occurs
    }
  }
  return result;
}

bool SnortHttpFilter::processRequest(const uint8_t* data, size_t size) {

  // Update ack for request. Ack all responses got so far.
  request_analyzer_->setAck(response_analyzer_->getSeq());

  bool allow = request_analyzer_->analyze(data, size, decoder_callbacks_->connection().ref());

  return allow;
}

bool SnortHttpFilter::processResponse(const uint8_t* data, size_t size) {

  // Update ack for response. Ack all requests got so far.
  response_analyzer_->setAck(request_analyzer_->getSeq());

  bool allow = response_analyzer_->analyze(data, size, encoder_callbacks_->connection().ref());

  return allow;
}

std::string SnortHttpFilter::serializeHeaders(const Http::HeaderMap& headers) {
  std::ostringstream result;

  // Serialize each header
  headers.iterate([&result](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
    auto key = std::string(header.key().getStringView());
    // Ignore key starting with ":" (e.g: ":authority", ":path", ":status")
    if (!key.empty() && key[0] == ':') {
      return Http::HeaderMap::Iterate::Continue;
    }
    auto val = header.value() != nullptr ? std::string(header.value().getStringView()) : "";
    result << key << ": " << val << "\r\n";
    return Http::HeaderMap::Iterate::Continue;
  });

  result << "\r\n"; // End of headers

  return result.str();
}

std::string SnortHttpFilter::serializeRequestHeaders(const Http::RequestHeaderMap& headers) {
  std::string result;

  // Serialize method and path
  absl::string_view method = headers.getMethodValue();
  absl::string_view scheme = headers.getSchemeValue();
  absl::string_view path = headers.getPathValue();
  absl::string_view host = headers.getHostValue();
  absl::string_view protocol = headers.getProtocolValue();
  if (protocol.empty()) {
    protocol = "HTTP/1.1";
  }

  ENVOY_LOG(
      trace,
      "snort serializeRequestHeaders: method: {}, scheme: {}, path: {}, host: {}, protocol: {}",
      method, scheme, path, host, protocol);

  // Add HTTP request line in payload (e.g:  GET http://example.com/xyz/ HTTP/1.1)
  result.append(method.data(), method.size());
  result.append(" ");
  result.append(scheme.data(), scheme.size());
  result.append("://");
  result.append(host.data(), host.size());
  result.append(path.data(), path.size());
  result.append(" ");
  result.append(protocol.data(), protocol.size());
  result.append("\r\n");

  // Serialize each header
  result += serializeHeaders(headers);

  ENVOY_LOG(trace, "snort serializeRequestHeaders: result: {}", result);
  return result;
}

std::string SnortHttpFilter::serializeRequestTrailers(const Http::RequestTrailerMap& trailers) {
  return serializeHeaders(trailers);
}

std::string SnortHttpFilter::serializeResponseHeaders(const Http::ResponseHeaderMap& headers) {
  std::string result;

  // Add HTTP version and status code
  auto status_code = std::string(headers.getStatusValue());
  if (status_code.empty() || !std::all_of(status_code.begin(), status_code.end(), ::isdigit)) {
    ENVOY_LOG(error, "Invalid or missing status code: {}", status_code);
    return ""; // Return an empty string or handle the error as needed
  }
  auto status_code_string =
      std::string(Http::CodeUtility::toString(static_cast<Http::Code>(std::stoi(status_code))));

  // Add HTTP response line in payload (e.g: HTTP/1.1 200 OK)
  std::string protocol = "HTTP/1.1";
  result += protocol + " " + status_code + " " + status_code_string + "\r\n";

  // Serialize each header if headers are valid
  if (!headers.empty()) {
    result += serializeHeaders(headers);
  }

  return result;
}

std::string SnortHttpFilter::serializeResponseTrailers(const Http::ResponseTrailerMap& trailers) {
  return serializeHeaders(trailers);
}

} // namespace SnortHttp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

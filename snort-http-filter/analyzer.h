#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"
#include "snort-http-filter/snorthttp.pb.h"
#include "source/common/buffer/buffer_impl.h"

namespace Envoy {
namespace Http {
/**
 * Traffic analayzer using snort.
 */
class BaseAnalyzer : public Logger::Loggable<Logger::Id::filter> {
public:
  BaseAnalyzer() = default;
  virtual ~BaseAnalyzer() = default;

  /**
   * Create Packet.
   */
  Buffer::OwnedImpl
  createPacket(const void* data, uint64_t size,
               const Network::Address::InstanceConstSharedPtr& source_address,
               const Network::Address::InstanceConstSharedPtr& destination_address);

  /**
   * Serialize Headers.
   */
  std::string serializeHeaders(const Http::HeaderMap& headers);

private:
  uint16_t checksum(const uint16_t* buf, size_t nwords);
};

class RequestAnalyzer : public virtual BaseAnalyzer {
public:
  virtual bool analyzeRequest(const Buffer::Instance&, const Http::RequestHeaderMap*,
                              const Http::RequestTrailerMap*, const Network::Connection&) {
    return true;
  }
  std::string serializeRequestHeaders(const Http::RequestHeaderMap& headers);
  std::string serializeRequestTrailers(const Http::RequestTrailerMap& trailers);
};

class ResponseAnalyzer : public virtual BaseAnalyzer {
public:
  virtual bool analyzeResponse(const Buffer::Instance&, const Http::ResponseHeaderMap*,
                               const Http::ResponseTrailerMap*, const Network::Connection&) {
    return true;
  }
  std::string serializeResponseHeaders(const Envoy::Http::ResponseHeaderMap& headers);
  std::string serializeResponseTrailers(const Http::ResponseTrailerMap& trailers);
};

class Analyzer : public RequestAnalyzer, public ResponseAnalyzer {
public:
  bool analyzeRequest(const Buffer::Instance& data, const Http::RequestHeaderMap* headers,
                      const Http::RequestTrailerMap* trailers,
                      const Network::Connection& connection) override;
  bool analyzeResponse(const Buffer::Instance& data, const Http::ResponseHeaderMap* headers,
                       const Http::ResponseTrailerMap* trailers,
                       const Network::Connection& connection) override;
};

} // namespace Http
} // namespace Envoy

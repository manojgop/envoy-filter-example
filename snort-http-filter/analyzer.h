#pragma once

#include "daq_manager.h"
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
  BaseAnalyzer();
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

  uint64_t getSeq() const { return seq_; }
  uint64_t getAck() const { return ack_; }
  void setSeq(uint64_t seq) { seq_ = seq; }
  void setAck(uint64_t ack) { ack_ = ack; }

protected:
  std::unique_ptr<DaqManager> daq_;

private:
  uint64_t seq_ = 0;
  uint64_t ack_ = 0;

  uint16_t checksum(const uint16_t* buf, int len);
};

class RequestAnalyzer : public virtual BaseAnalyzer {
public:
  virtual bool analyzeRequest(const uint8_t* data, size_t size, const Http::RequestHeaderMap*,
                              const Http::RequestTrailerMap*, const Network::Connection&);
  std::string serializeRequestHeaders(const Http::RequestHeaderMap& headers);
  std::string serializeRequestTrailers(const Http::RequestTrailerMap& trailers);
};

class ResponseAnalyzer : public virtual BaseAnalyzer {
public:
  virtual bool analyzeResponse(const uint8_t* data, size_t size, const Http::ResponseHeaderMap*,
                               const Http::ResponseTrailerMap*, const Network::Connection&);
  std::string serializeResponseHeaders(const Envoy::Http::ResponseHeaderMap& headers);
  std::string serializeResponseTrailers(const Http::ResponseTrailerMap& trailers);
};

} // namespace Http
} // namespace Envoy

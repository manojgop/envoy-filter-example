#pragma once

#include "daq_manager.h"
#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"
#include "snort-http-filter/snorthttp.pb.h"
#include "source/common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SnortHttp {

/**
 * Traffic analayzer using snort.
 */
class BaseAnalyzer : public Logger::Loggable<Logger::Id::filter> {
public:
  BaseAnalyzer();
  virtual ~BaseAnalyzer() = default;

  virtual bool analyze(const uint8_t* data, size_t size, const Network::Connection&) = 0;

  /**
   * Create Packet.
   */
  Buffer::OwnedImpl
  createPacket(const void* data, uint64_t size,
               const Network::Address::InstanceConstSharedPtr& source_address,
               const Network::Address::InstanceConstSharedPtr& destination_address);

  uint64_t getSeq() const { return seq_; }
  uint64_t getAck() const { return ack_; }
  void setSeq(uint64_t seq) { seq_ = seq; }
  void setAck(uint64_t ack) { ack_ = ack; }

protected:
  std::unique_ptr<DaqManager> daq_;

private:
  uint64_t seq_;
  uint64_t ack_;

  uint16_t checksum(const uint16_t* buf, int len);
  uint32_t generateRandomNumber();
};

class RequestAnalyzer : public virtual BaseAnalyzer {
public:
  RequestAnalyzer(bool enable_save_pcap, bool enable_analyze, const std::string& unix_socket_path);
  virtual bool analyze(const uint8_t* data, size_t size, const Network::Connection&);

private:
  const bool enable_save_pcap_;
  const bool enable_analyze_;
  const std::string unix_socket_path_;
};

class ResponseAnalyzer : public virtual BaseAnalyzer {
public:
  ResponseAnalyzer(bool enable_save_pcap, bool enable_analyze, const std::string& unix_socket_path);
  virtual bool analyze(const uint8_t* data, size_t size, const Network::Connection&);

private:
  const bool enable_save_pcap_;
  const bool enable_analyze_;
  const std::string unix_socket_path_;
};

} // namespace SnortHttp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

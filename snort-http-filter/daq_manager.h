#pragma once

#include "source/common/common/logger.h"
#include <string>
#include <memory>

#define DAQ_MANAGER_MAX_DATA_SIZE 1518

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SnortHttp {

class DaqManager : public Logger::Loggable<Logger::Id::filter> {
public:
  DaqManager();
  ~DaqManager();

  bool sendPacketToDaq(const uint8_t* data, size_t length);
  bool getVerdictFromDaq();

private:
  const char* kUnixSocketPath = "/tmp/envoy.sock";
  int unix_socket_fd_;
  enum DaqEnvoyMsgType {
    DAQ_ENVOY_MSG_TYPE_NONE = 0,
    DAQ_ENVOY_MSG_TYPE_HELLO = 1,
    DAQ_ENVOY_MSG_TYPE_CONFIG = 2,
    DAQ_ENVOY_MSG_TYPE_BPOOL = 3,
    DAQ_ENVOY_MSG_TYPE_QPAIR = 4,
    DAQ_ENVOY_MSG_TYPE_PACKET = 5,
  };

  // Should match DAQ_Verdict enum in https://github.com/snort3/libdaq/blob/master/api/daq_common.h
  enum DaqVerdict {
    DAQ_VERDICT_PASS,    /* Pass the packet. */
    DAQ_VERDICT_BLOCK,   /* Block the packet. */
    DAQ_VERDICT_REPLACE, /* Pass a packet that has been modified in-place. (No resizing allowed!) */
    DAQ_VERDICT_WHITELIST, /* Pass the packet and fastpath all future packets in the same flow
                              systemwide. */
    DAQ_VERDICT_BLACKLIST, /* Block the packet and block all future packets in the same flow
                              systemwide. */
    DAQ_VERDICT_IGNORE, /* Pass the packet and fastpath all future packets in the same flow for this
                           application. */
    MAX_DAQ_VERDICT
  };

  bool connectSocket();
};

} // namespace SnortHttp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

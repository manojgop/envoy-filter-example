#include "daq_manager.h"
#include <algorithm>
#include <ctime>
#include <chrono>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SnortHttp {

DaqManager::DaqManager() {
  ENVOY_LOG(trace, "Snort DAQ manager: Create");
  // Create and Connect to Snort process if not yet connected
  connectSocket();
}

DaqManager::~DaqManager() {
  ENVOY_LOG(trace, "Snort DAQ manager: Destroy");
  if (unix_socket_fd_ > 0) {
    close(unix_socket_fd_);
    unix_socket_fd_ = -1;
  }
}

bool DaqManager::connectSocket() {
  unix_socket_fd_ = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (unix_socket_fd_ < 0) {
    ENVOY_LOG(error, "Snort DAQ manager: Unix socket creation failed: {}", strerror(errno));
    return false;
  }
  struct sockaddr_un server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sun_family = AF_UNIX;
  strncpy(server_addr.sun_path, kUnixSocketPath, sizeof(server_addr.sun_path) - 1);

  if (connect(unix_socket_fd_, reinterpret_cast<struct sockaddr*>(&server_addr),
              sizeof(server_addr)) < 0) {
    ENVOY_LOG(error, "Snort DAQ manager: Connection to server failed on {} : {}", kUnixSocketPath,
              strerror(errno));
    close(unix_socket_fd_);
    unix_socket_fd_ = -1;
    return false;
  }
  return true;
}

bool DaqManager::sendPacketToDaq(const uint8_t* data, size_t length) {

  // Create and connect to snort process if not yet connected
  if (unix_socket_fd_ < 0) {
    if (!connectSocket()) {
      return false;
    }
  }

  // Send packet data
  if (send(unix_socket_fd_, data, length, 0) == -1) {
    ENVOY_LOG(error, "Snort DAQ manager: Sending data failed: {}", strerror(errno));
    return false;
  }

  return true;
}

bool DaqManager::getVerdictFromDaq() {
  DaqVerdict verdict = DAQ_VERDICT_BLOCK;
  int ret = recv(unix_socket_fd_, &verdict, sizeof(verdict), 0);
  if (ret < 0) {
    ENVOY_LOG(error, "Snort DAQ manager: Receiving message failed: {}", strerror(errno));
    return false;
  }
  if (verdict == DAQ_VERDICT_BLOCK || verdict == DAQ_VERDICT_BLACKLIST) {
    return false;
  }
  return true;
}

} // namespace SnortHttp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

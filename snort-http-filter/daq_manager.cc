#include "daq_manager.h"
#include <algorithm>
#include <ctime>
#include <chrono>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>

namespace Envoy {
namespace Http {

DaqManager::DaqManager() {
  // Create and Connect to Snort process if not yet connected
  connectSocket();
}

DaqManager::~DaqManager() {
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
  // std::lock_guard<std::mutex> lock(mutex_);

  // Create and connect to snort process if not yet connected
  if (unix_socket_fd_ < 0) {
    if (!connectSocket()) {
      return false;
    }
  }

  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

  struct pcap_pkthdr pcap_header;
  pcap_header.ts.tv_sec = static_cast<int64_t>(microseconds / 1000000);
  pcap_header.ts.tv_usec = static_cast<int64_t>(microseconds % 1000000);
  pcap_header.caplen = length;
  pcap_header.len = length;

  // Send pcap header
  if (send(unix_socket_fd_, &pcap_header, sizeof(pcap_header), 0) == -1) {
    ENVOY_LOG(error, "Snort DAQ manager: Sending pcap header failed: {}", strerror(errno));
    return false;
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
  if (verdict != DAQ_VERDICT_PASS) {
    return false;
  }
  return true;
}

} // namespace Http
} // namespace Envoy
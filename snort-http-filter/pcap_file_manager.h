#pragma once

#include <pcap.h>
#include <string>
#include <memory>
#include <mutex>

class PcapFileManager {
public:
  static PcapFileManager& getInstance() {
    static PcapFileManager instance;
    return instance;
  }

  void writeToPcap(const uint8_t* data, size_t length);

private:
  PcapFileManager();
  ~PcapFileManager();

  pcap_t* pcap_;
  pcap_dumper_t* dumper_;
  std::mutex mutex_;

  // Delete copy constructor and assignment operator
  PcapFileManager(const PcapFileManager&) = delete;
  PcapFileManager& operator=(const PcapFileManager&) = delete;
};

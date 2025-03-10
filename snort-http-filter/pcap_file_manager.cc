#include "pcap_file_manager.h"
#include <ctime>
#include <chrono>

PcapFileManager::PcapFileManager() {
  pcap_ = pcap_open_dead(DLT_EN10MB, 65535);
  dumper_ = pcap_dump_open(pcap_, "output.pcap");
}

PcapFileManager::~PcapFileManager() {
  pcap_dump_close(dumper_);
  pcap_close(pcap_);
}

void PcapFileManager::writeToPcap(const uint8_t* data, size_t length) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

  struct pcap_pkthdr pcap_header;
  pcap_header.ts.tv_sec = static_cast<int64_t>(microseconds / 1000000);
  pcap_header.ts.tv_usec = static_cast<int64_t>(microseconds % 1000000);
  pcap_header.caplen = length;
  pcap_header.len = length;

  pcap_dump(reinterpret_cast<u_char*>(dumper_), &pcap_header, data);
  pcap_dump_flush(dumper_);
}

#pragma once

#include <string>

#include "snort.h"

#include "snort-filter/snort.pb.h"
#include "snort-filter/snort.pb.validate.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the snort filter. @see NamedNetworkFilterConfigFactory.
 */
class SnortConfigFactory : public NamedNetworkFilterConfigFactory {
public:
  absl::StatusOr<Network::FilterFactoryCb> createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                        FactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new snort::SnortConfig()};
  }

  std::string name() const override { return "snort"; }

  bool isTerminalFilterByProto(const Protobuf::Message&, ServerFactoryContext&) override { return false; }
};


} // namespace Configuration
} // namespace Server
} // namespace Envoy

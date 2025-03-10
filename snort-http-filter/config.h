#pragma once

#include <string>

#include "snort_http.h"

#include "snort-http-filter/snorthttp.pb.h"
#include "snort-http-filter/snorthttp.pb.validate.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the snort http filter. @see NamedNetworkFilterConfigFactory.
 */
class SnortHttpFilterConfigFactory : public NamedHttpFilterConfigFactory {
public:
  absl::StatusOr<Http::FilterFactoryCb>
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               FactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override;
  bool isTerminalFilterByProto(const Protobuf::Message&, ServerFactoryContext&) override {
    return false;
  }
};

} // namespace Configuration
} // namespace Server
} // namespace Envoy

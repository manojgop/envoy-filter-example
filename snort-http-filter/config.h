#pragma once

#include <string>

#include "snort_http.h"
#include "absl/status/statusor.h"
#include "snort-http-filter/snorthttp.pb.h"
#include "snort-http-filter/snorthttp.pb.validate.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SnortHttp {

/**
 * Config registration for the snort http filter. @see NamedNetworkFilterConfigFactory.
 */
class SnortHttpFilterConfigFactory : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  absl::StatusOr<Http::FilterFactoryCb>
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               Server::Configuration::FactoryContext& context) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override;
  bool isTerminalFilterByProto(const Protobuf::Message&,
                               Server::Configuration::ServerFactoryContext&) override {
    return false;
  }
};

} // namespace SnortHttp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

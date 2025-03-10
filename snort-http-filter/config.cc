#include <string>

#include "config.h"
#include "snort-http-filter/snorthttp.pb.h"
#include "snort-http-filter/snorthttp.pb.validate.h"

#include "snort_http.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

absl::StatusOr<Http::FilterFactoryCb> SnortHttpFilterConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message& proto_config, const std::string&, FactoryContext& context) {

  snort::SnortHttpConfig snort_http_proto_config =
      Envoy::MessageUtil::downcastAndValidate<const snort::SnortHttpConfig&>(
          proto_config, context.messageValidationVisitor());

  Http::SnortHttpFilterConfigSharedPtr config(
      std::make_shared<Http::SnortHttpFilterConfig>(snort_http_proto_config, context.scope()));

  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    auto filter = new Http::SnortHttpFilter(config);
    callbacks.addStreamFilter(Http::StreamFilterSharedPtr{filter});
  };
}

ProtobufTypes::MessagePtr SnortHttpFilterConfigFactory::createEmptyConfigProto() {
  return ProtobufTypes::MessagePtr{new snort::SnortHttpConfig()};
}

std::string SnortHttpFilterConfigFactory::name() const { return "snorthttp"; }

/**
 * Static registration for the snort filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<SnortHttpFilterConfigFactory, NamedHttpFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy

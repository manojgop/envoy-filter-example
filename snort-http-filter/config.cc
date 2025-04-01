#include <string>

#include "config.h"
#include "snort-http-filter/snorthttp.pb.h"
#include "snort-http-filter/snorthttp.pb.validate.h"

#include "snort_http.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SnortHttp {

absl::StatusOr<Http::FilterFactoryCb> SnortHttpFilterConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message& proto_config, const std::string&,
    Server::Configuration::FactoryContext& context) {

  envoy::filters::http::snort::SnortHttpConfig snort_http_proto_config =
      Envoy::MessageUtil::downcastAndValidate<const envoy::filters::http::snort::SnortHttpConfig&>(
          proto_config, context.messageValidationVisitor());

  SnortHttpFilterConfigSharedPtr config(
      std::make_shared<SnortHttpFilterConfig>(snort_http_proto_config, context.scope()));

  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    auto filter = new SnortHttpFilter(config);
    callbacks.addStreamFilter(Http::StreamFilterSharedPtr{filter});
  };
}

ProtobufTypes::MessagePtr SnortHttpFilterConfigFactory::createEmptyConfigProto() {
  return ProtobufTypes::MessagePtr{new envoy::filters::http::snort::SnortHttpConfig()};
}

std::string SnortHttpFilterConfigFactory::name() const { return "envoy.filters.http.snort"; }

/**
 * Static registration for the snort filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<SnortHttpFilterConfigFactory,
                                 Server::Configuration::NamedHttpFilterConfigFactory>
    registered_;

} // namespace SnortHttp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

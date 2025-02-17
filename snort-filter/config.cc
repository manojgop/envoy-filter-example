#include <string>

#include "config.h"
#include "snort-filter/snort.pb.h"
#include "snort-filter/snort.pb.validate.h"

#include "snort.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the snort filter. @see NamedNetworkFilterConfigFactory.
 */
absl::StatusOr<Network::FilterFactoryCb> SnortConfigFactory::createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                      FactoryContext& context) {
  snort::SnortConfig snort_proto_config = Envoy::MessageUtil::downcastAndValidate<const snort::SnortConfig&>(
                          proto_config, context.messageValidationVisitor());
  Filter::SnortFilterConfigSharedPtr config(
    std::make_shared<Filter::SnortFilterConfig>(snort_proto_config, context.scope()));
  return [config](Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(Network::ReadFilterSharedPtr{new Filter::Snort(config)});
  };
}


/**
 * Static registration for the snort filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<SnortConfigFactory, NamedNetworkFilterConfigFactory> registered_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy

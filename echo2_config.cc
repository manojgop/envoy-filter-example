#include <string>

#include "echo2.h"

#include "echo_config.pb.h"
#include "echo_config.pb.validate.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the echo2 filter. @see NamedNetworkFilterConfigFactory.
 */
class Echo2ConfigFactory : public NamedNetworkFilterConfigFactory {
public:
  absl::StatusOr<Network::FilterFactoryCb> createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                        FactoryContext& context) override {
    echoconfig::EchoConfig echo_proto_config = Envoy::MessageUtil::downcastAndValidate<const echoconfig::EchoConfig&>(
                            proto_config, context.messageValidationVisitor());
    Filter::Echo2FilterConfigSharedPtr config(
      std::make_shared<Filter::Echo2FilterConfig>(echo_proto_config, context.scope()));
    return [config](Network::FilterManager& filter_manager) -> void {
      filter_manager.addReadFilter(Network::ReadFilterSharedPtr{new Filter::Echo2(config)});
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new echoconfig::EchoConfig()};
  }

  std::string name() const override { return "echo2"; }

  bool isTerminalFilterByProto(const Protobuf::Message&, ServerFactoryContext&) override { return true; }
};

/**
 * Static registration for the echo2 filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<Echo2ConfigFactory, NamedNetworkFilterConfigFactory> registered_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy

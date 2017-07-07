#include <pxp-agent/modules/echo.hpp>
#include <pxp-agent/module_type.hpp>

#include <utility>  // std::move

namespace PXPAgent {
namespace Modules {

namespace lth_jc = leatherman::json_container;

static const std::string ECHO { "echo" };

Echo::Echo() {
    module_name = ECHO;
    actions.push_back(ECHO);
    PCPClient::Schema input_schema { ECHO };
    input_schema.addConstraint("argument", PCPClient::TypeConstraint::String,
                               true);

    input_validator_.registerSchema(input_schema);
}

ActionResponse Echo::callAction(const ActionRequest& request) {
    auto params = request.params();

    assert(params.includes("argument")
           && params.type("argument") == lth_jc::DataType::String);

    ActionResponse response { ModuleType::Internal, request };
    lth_jc::JsonContainer results {};
    results.set<std::string>("outcome", params.get<std::string>("argument"));
    response.setValidResultsAndEnd(std::move(results));
    return response;
}

}  // namespace Modules
}  // namespace PXPAgent

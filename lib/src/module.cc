#include <pxp-agent/module.hpp>
#include <pxp-agent/action_status.hpp>

#define LEATHERMAN_LOGGING_NAMESPACE "puppetlabs.pxp_agent.module"
#include <leatherman/logging/logging.hpp>

#include <leatherman/locale/locale.hpp>

#include <iostream>
#include <algorithm>

namespace PXPAgent {

namespace lth_jc  = leatherman::json_container;
namespace lth_loc = leatherman::locale;

Module::Module()
        : input_validator_ {}
{
}

bool Module::hasAction(const std::string& action_name)
{
    return std::find(actions.begin(), actions.end(), action_name)
           != actions.end();
}

ActionResponse Module::executeAction(const ActionRequest& request)
{
    std::string err_msg {};

    try {
        auto response = callAction(request);
        assert(response.valid()
                && response.action_metadata.includes("results_are_valid"));

        if (!response.action_metadata.get<bool>("results_are_valid")) {
            // We expect that the action's output is not valid JSON
            assert(response.action_metadata.includes("execution_error"));
            return response;
        }

        assert(response.action_metadata.includes("results"));
        return response;
    } catch (const Module::ProcessingError& e) {
        err_msg += lth_loc::format("Error: {1}", e.what());
    } catch (std::exception& e) {
        err_msg += lth_loc::format("Unexpected error: {1}", e.what());
    } catch (...) {
        err_msg = lth_loc::translate("Unexpected exception.");
    }

    std::string execution_error {
         lth_loc::format("Failed to execute the task for the {1}. {2}",
                         request.prettyLabel(), err_msg) };
    LOG_ERROR(execution_error);
    ActionResponse r { type(), request };
    r.setBadResultsAndEnd(execution_error);
    return r;
}

}  // namespace PXPAgent

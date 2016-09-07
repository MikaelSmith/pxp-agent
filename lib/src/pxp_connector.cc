#include <pxp-agent/pxp_connector.hpp>
#include <pxp-agent/pxp_schemas.hpp>
#include <pxp-agent/agent.hpp>

#include <cpp-pcp-client/connector/client_metadata.hpp>
#include <cpp-pcp-client/connector/errors.hpp>

#include <leatherman/util/thread.hpp>   // this_thread::sleep_for
#include <leatherman/util/chrono.hpp>

#define LEATHERMAN_LOGGING_NAMESPACE "puppetlabs.pxp_agent.pxp_connector"
#include <leatherman/logging/logging.hpp>

#include <utility>
#include <vector>
#include <cstdint>
#include <random>

#include <nats.h>

namespace PXPAgent {

namespace lth_jc = leatherman::json_container;
namespace lth_util = leatherman::util;
namespace lth_loc = leatherman::locale;

PXPConnector::PXPConnector(const Configuration::Agent& agent_configuration)
    try
        : conn_ { nullptr },
          request_sub_ { nullptr },
          broker_uris_ { agent_configuration.broker_ws_uris },
          ca_ { agent_configuration.ca },
          crt_ { agent_configuration.crt },
          key_ { agent_configuration.key },
          common_name_ { PCPClient::getCommonNameFromCert(crt_) },
          connection_timeout_ms_ { agent_configuration.ws_connection_timeout_ms },
          pong_timeouts_before_retry_ { agent_configuration.allowed_keepalive_timeouts+1 },
          connected_ { false }
{
    LOG_INFO("Retrieved common name from the certificate: {1}", common_name_);
    PCPClient::validatePrivateKeyCertPair(key_, crt_);
    LOG_DEBUG("Validated the private key / certificate pair");
} catch (const PCPClient::connection_config_error& e) {
    throw Agent::WebSocketConfigurationError { e.what() };
}

PXPConnector::~PXPConnector()
{
    if (request_sub_) {
        natsSubscription_Destroy(request_sub_);
    }

    if (conn_) {
        natsConnection_Destroy(conn_);
    }
}

void PXPConnector::sendProvisionalResponse(const ActionRequest& request)
{
    assert(conn_ && request_sub_);

    lth_jc::JsonContainer provisional_data {};
    provisional_data.set<std::string>("transaction_id", request.transactionId());

    std::string data = provisional_data.toString();
    auto s = natsConnection_Publish(conn_, request.sender().c_str(), data.c_str(), data.size());
    if (s == NATS_OK) {
        LOG_INFO("Sent provisional response for the {1} by {2}",
                 request.prettyLabel(), request.sender());
    } else {
        LOG_ERROR("Failed to send provisional response for the {1} by {2} "
                  "(no further attempts will be made): {3}",
                  request.prettyLabel(), request.sender(), natsStatus_GetText(s));
    }
}

void PXPConnector::sendPXPError(const ActionRequest& request,
                                const std::string& description)
{
    assert(conn_ && request_sub_);

    lth_jc::JsonContainer pxp_error_data {};
    pxp_error_data.set<std::string>("transaction_id", request.transactionId());
    pxp_error_data.set<std::string>("id", request.id());
    pxp_error_data.set<std::string>("description", description);

    std::string data = pxp_error_data.toString();
    auto s = natsConnection_Publish(conn_, request.sender().c_str(), data.c_str(), data.size());
    if (s == NATS_OK) {
        LOG_INFO("Replied to {1} by {2}, request ID {3}, with a PXP error message",
                 request.prettyLabel(), request.sender(), request.id());
    } else {
        LOG_ERROR("Failed to send a PXP error message for the {1} by {2} "
                  "(no further sending attempts will be made): {3}\n{4}",
                  request.prettyLabel(), request.sender(), natsStatus_GetText(s), description);
    }
}

void PXPConnector::sendPXPError(const ActionResponse& response)
{
    assert(response.valid(ActionResponse::ResponseType::RPCError));
    assert(conn_ && request_sub_);

    std::string data = response.toJSON(ActionResponse::ResponseType::RPCError).toString();
    auto requestor = response.action_metadata.get<std::string>("requester");
    auto s = natsConnection_Publish(conn_, requestor.c_str(),
                                    data.c_str(), data.size());
    if (s == NATS_OK) {
        LOG_INFO("Replied to {1} by {2}, request ID {3}, with a PXP error message",
                 response.prettyRequestLabel(),
                 requestor,
                 response.action_metadata.get<std::string>("request_id"));
    } else {
        LOG_ERROR("Failed to send a PXP error message for the {1} by {2} "
                  "(no further sending attempts will be made): {3}\n{3}",
                  response.prettyRequestLabel(),
                  requestor,
                  natsStatus_GetText(s),
                  response.action_metadata.get<std::string>("execution_error"));
    }
}

void PXPConnector::sendBlockingResponse(const ActionResponse& response,
                                        const ActionRequest& request)
{
    assert(response.valid(ActionResponse::ResponseType::Blocking));
    assert(conn_ && request_sub_);

    sendBlockingResponse_(ActionResponse::ResponseType::Blocking,
                          response,
                          request);
}

void PXPConnector::sendStatusResponse(const ActionResponse& response,
                                      const ActionRequest& request)
{
    assert(response.valid(ActionResponse::ResponseType::StatusOutput));
    assert(conn_ && request_sub_);

    sendBlockingResponse_(ActionResponse::ResponseType::StatusOutput,
                          response,
                          request);
}

void PXPConnector::sendNonBlockingResponse(const ActionResponse& response)
{
    assert(response.valid(ActionResponse::ResponseType::NonBlocking));
    assert(response.action_metadata.get<std::string>("status") != "undetermined");
    assert(conn_ && request_sub_);

    std::string data = response.toJSON(ActionResponse::ResponseType::NonBlocking).toString();
    auto requestor = response.action_metadata.get<std::string>("requester");
    auto s = natsConnection_Publish(conn_, requestor.c_str(),
                                    data.c_str(), data.size());
    if (s == NATS_OK) {
        LOG_INFO("Sent response for the {1} by {2}",
                 response.prettyRequestLabel(),
                 response.action_metadata.get<std::string>("requester"));
    } else {
        LOG_ERROR("Failed to reply to {1} by {2}, (no further attempts will "
                  "be made): {3}",
                  response.prettyRequestLabel(),
                  response.action_metadata.get<std::string>("requester"),
                  natsStatus_GetText(s));
    }
}

void PXPConnector::dispatchMsg(std::string subj, std::string reply, lth_jc::JsonContainer data)
{
    MessageCallback cb;
    for (auto &p : callbacks_) {
        try {
            validator_.validate(data, p.first);
            LOG_DEBUG("Matched message type {1}", p.first);
            cb = p.second;
            break;
        } catch (lth_jc::validator_error& e) {
            LOG_DEBUG("Message not of type {1}", p.first);
        }
    }

    if (cb) {
        cb(std::move(subj), std::move(reply), std::move(data), {});
    } else {
        LOG_ERROR("Message did not match a known schema: {1}");
    }
}

static void onMsg(natsConnection *nc, natsSubscription *sub, natsMsg *msg, void *_conn)
{
    auto conn = reinterpret_cast<PXPConnector*>(_conn);

    std::string data(natsMsg_GetData(msg), natsMsg_GetDataLength(msg));
    std::string subj = natsMsg_GetSubject(msg);
    std::string reply = natsMsg_GetReply(msg);
    natsMsg_Destroy(msg);

    LOG_INFO("Received msg: {1}:{2} - {3}", subj, reply, data);

    if (reply.empty()) {
        LOG_ERROR("Unable to handle message without reply queue specified");
        return;
    }

    try {
        conn->dispatchMsg(std::move(subj), std::move(reply), lth_jc::JsonContainer(data));
    } catch (const lth_jc::data_parse_error& e) {
        LOG_ERROR("Invalid JSON content: {1}", e.what());
    }
}

static void onConn(natsConnection *nc, void *closure)
{
    LOG_INFO("Connected");
    *reinterpret_cast<bool*>(closure) = true;
}

static void onDisc(natsConnection *nc, void *closure)
{
    LOG_INFO("Disconnected");
    *reinterpret_cast<bool*>(closure) = false;
    LOG_INFO("Connecting...");
}

void PXPConnector::connect()
{
    std::vector<const char*> servers;
    for (auto &uri : broker_uris_) {
        servers.push_back(uri.c_str());
    }

    // TODO: Handle errors
    natsOptions *opts = nullptr;
    natsOptions_Create(&opts);
    natsOptions_SetServers(opts, servers.data(), servers.size());
    natsOptions_SetReconnectWait(opts, 2000);
    natsOptions_SetMaxPingsOut(opts, pong_timeouts_before_retry_);
    natsOptions_SetPingInterval(opts, 15000);
    natsOptions_SetTimeout(opts, connection_timeout_ms_);

    natsOptions_SetSecure(opts, true);
    // TODO: Figure out how to handle expected hostname with multiple servers.
    //natsOptions_SetExpectedHostname(opts, "broker.example.com");
    natsOptions_LoadCATrustedCertificates(opts, ca_.c_str());
    natsOptions_LoadCertificatesChain(opts, crt_.c_str(), key_.c_str());

    natsOptions_SetDisconnectedCB(opts, onDisc, &connected_);
    natsOptions_SetReconnectedCB(opts, onConn, &connected_);

    auto stat = natsConnection_Connect(&conn_, opts);
    while (stat == NATS_NO_SERVER) {
        LOG_INFO("Server unavailable, retrying again in 2 seconds");
        nats_Sleep(2000);
        stat = natsConnection_Connect(&conn_, opts);
    }

    if (stat != NATS_OK) {
        LOG_WARNING("NATS error: {1}", natsStatus_GetText(stat));
        return;
    }
    LOG_INFO("Connected");

    connected_ = true;
    LOG_INFO("Subscribing to queue {1}", common_name_);
    natsConnection_Subscribe(&request_sub_, conn_, common_name_.c_str(), onMsg, this);
    while (true) {
        nats_Sleep(5000);
    }
}

void PXPConnector::registerMessageCallback(leatherman::json_container::Schema schema,
                                           MessageCallback callback)
{
    callbacks_.push_back(std::make_pair(schema.getName(), std::move(callback)));
    validator_.registerSchema(std::move(schema));
}


//
// Private interface
//

void PXPConnector::sendBlockingResponse_(
        const ActionResponse::ResponseType& response_type,
        const ActionResponse& response,
        const ActionRequest& request)
{
    std::string data = response.toJSON(response_type).toString();
    auto s = natsConnection_Publish(conn_, request.sender().c_str(), data.c_str(), data.size());
    if (s == NATS_OK) {
        LOG_INFO("Sent response for the message for {1} by {2}", request.prettyLabel(), request.sender());
    } else {
        LOG_ERROR("Failed to reply to the {1} by {2}: {3}",
                  request.prettyLabel(), request.sender(), natsStatus_GetText(s));
    }
}

}  // namesapce PXPAgent

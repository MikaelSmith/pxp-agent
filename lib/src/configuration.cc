#include <pxp-agent/configuration.hpp>
#include <pxp-agent/time.hpp>

#include "version-inl.hpp"

#include <cpp-pcp-client/util/logging.hpp>
#include <cpp-pcp-client/connector/client_metadata.hpp>  // validate SSL certs
#include <cpp-pcp-client/connector/errors.hpp>

#include <leatherman/locale/locale.hpp>

#include <leatherman/file_util/file.hpp>

#include <leatherman/util/strings.hpp>

#include <leatherman/json_container/json_container.hpp>

#define LEATHERMAN_LOGGING_NAMESPACE "puppetlabs.pxp_agent.configuration"
#include <leatherman/logging/logging.hpp>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <boost/nowide/iostream.hpp>

#ifdef _WIN32
    #include <leatherman/windows/system_error.hpp>
    #include <leatherman/windows/windows.hpp>
    #undef ERROR
    #include <Shlobj.h>
#endif

namespace PXPAgent {

namespace HW = HorseWhisperer;
namespace fs = boost::filesystem;
namespace lth_file = leatherman::file_util;
namespace lth_jc   = leatherman::json_container;
namespace lth_log  = leatherman::logging;
namespace lth_loc  = leatherman::locale;
namespace lth_util = leatherman::util;

//
// Default values
//

#ifdef _WIN32
    namespace lth_w = leatherman::windows;
    static const fs::path DATA_DIR = []() {
        wchar_t szPath[MAX_PATH+1];
        if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szPath))) {
            throw Configuration::Error {
                lth_loc::format("failure getting Windows AppData directory: {1}",
                                lth_w::system_error()) };
        }
        return fs::path(szPath) / "PuppetLabs" / "pxp-agent";
    }();

    static const fs::path DEFAULT_CONF_DIR { DATA_DIR / "etc" };
    const std::string DEFAULT_SPOOL_DIR { (DATA_DIR / "var" / "spool").string() };
    static const std::string DEFAULT_LOG_FILE {
        (DATA_DIR / "var" / "log" / "pxp-agent.log").string() };

    static const std::string DEFAULT_MODULES_DIR = []() {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0) {
            throw Configuration::Error {
                lth_loc::translate("failed to retrive pxp-agent binary path") };
        }
        // Go up twice, assuming the subtree from Puppet Specs:
        //      C:\Program Files\Puppet Labs\Puppet\pxp-agent
        //          bin
        //              pxp-agent.exe
        //          modules
        //              pxp-module-puppet
        try {
            return (fs::path(szPath).parent_path().parent_path() / "modules").string();
        } catch (const std::exception& e) {
            throw Configuration::Error {
                lth_loc::format("failed to determine the modules directory path: {1}",
                                e.what()) };
        }
    }();
#else
    static const fs::path DEFAULT_CONF_DIR { "/etc/puppetlabs/pxp-agent" };
    const std::string DEFAULT_SPOOL_DIR { "/opt/puppetlabs/pxp-agent/spool" };
    static const std::string DEFAULT_PID_FILE { "/var/run/puppetlabs/pxp-agent.pid" };
    static const std::string DEFAULT_LOG_FILE { "/var/log/puppetlabs/pxp-agent/pxp-agent.log" };
    static const std::string DEFAULT_MODULES_DIR { "/opt/puppetlabs/pxp-agent/modules" };
#endif

static const std::string DEFAULT_MODULES_CONF_DIR {
    (DEFAULT_CONF_DIR / "modules").string() };
static const std::string DEFAULT_CONFIG_FILE {
    (DEFAULT_CONF_DIR / "pxp-agent.conf").string() };
static const std::string DEFAULT_SPOOL_DIR_PURGE_TTL { "14d" };

static const std::string AGENT_CLIENT_TYPE { "agent" };

//
// Public interface
//

void Configuration::initialize(
        std::function<int(std::vector<std::string>)> start_function)
{
    // Ensure the state is reset (useful for testing)
    HW::Reset();
    HW::SetAppName("pxp-agent");
    HW::SetHelpBanner(lth_loc::translate("Usage: pxp-agent [options]"));
    HW::SetVersion(std::string { PXP_AGENT_VERSION } + "\n");
    valid_ = false;

    // Initialize boost filesystem's locale to a UTF-8 default.
    // Logging gets setup the same way via the default 2nd argument.
#ifdef LEATHERMAN_USE_LOCALES
    // Locale support in GCC on Solaris is busted, so skip it.
    fs::path::imbue(lth_loc::get_locale());
#endif

    setDefaultValues();

    // NOTE(ale): don't need to translate this (forced default action)
    HW::DefineAction("start",                       // action name
                     0,                             // arity
                     false,                         // chainable
                     "Start the agent (Default)",   // description
                     "Start the agent",             // help string
                     start_function);               // callback
}

HW::ParseResult parseArguments(const int argc, char* const argv[])
{
    // manipulate argc and v to make start the default action.
    // TODO(ploubser): Add ability to specify default action to HorseWhisperer
    int modified_argc = argc + 1;
    char* modified_argv[modified_argc];
    char action[] = "start";

    for (int i = 0; i < argc; i++) {
        modified_argv[i] = argv[i];
    }
    modified_argv[modified_argc - 1] = action;

    return HW::Parse(modified_argc, modified_argv);
}

HW::ParseResult Configuration::parseOptions(int argc, char *argv[])
{
    auto parse_result = parseArguments(argc, argv);

    if (parse_result == HW::ParseResult::FAILURE
        || parse_result == HW::ParseResult::INVALID_FLAG) {
        throw Configuration::Error {
            lth_loc::translate("An error occurred while parsing cli options") };
    }

    if (parse_result == HW::ParseResult::OK) {
        if (!config_file_.empty()) {
            parseConfigFile();
        }
    }
    // No further processing or user interaction are required if
    // the parsing outcome is HW::ParseResult::HELP or VERSION

    return parse_result;
}

static void validateLogDirPath(const std::string& logfile)
{
    auto logdir_path = fs::path(logfile).parent_path();

    if (fs::exists(logdir_path)) {
        if (!fs::is_directory(logdir_path)) {
            throw Configuration::Error {
                lth_loc::format("cannot write to the specified logfile; '{1}' is "
                                "not a directory", logdir_path.string()) };
        }
    } else {
        throw Configuration::Error {
            lth_loc::format("cannot write to '{1}'; its parent directory does "
                            "not exist", logfile) };
    }
}

void Configuration::setupLogging()
{
    auto log_on_stdout = (logfile_ == "-");
    std::ostream *stream = nullptr;

    if (!log_on_stdout) {
        // We should log on file
        logfile_ = lth_file::tilde_expand(logfile_);

        // NOTE(ale): we must validate the logifle path since we set
        // up logging before calling validateAndNormalizeConfiguration
        validateLogDirPath(logfile_);

        logfile_fstream_.open(logfile_.c_str(), std::ios_base::app);
        stream = &logfile_fstream_;
    } else {
        stream = &boost::nowide::cout;
    }

#ifndef _WIN32
    if (!foreground_ && log_on_stdout) {
        // NOTE(ale): util/posix/daemonize.cc will ensure that the
        // daemon is not associated with any controlling terminal.
        // It will also redirect stdout to /dev/null, together
        // with the other standard files. Set log_level to none to
        // reduce useless overhead since logfile is set to stdout.
        loglevel_ = "none";
    }
#endif

    lth_log::log_level lvl = lth_log::log_level::none;
    try {
        // NOTE(ale): ignoring HorseWhisperer's vlevel ("-v" flag)
        const std::map<std::string, lth_log::log_level> option_to_log_level {
            { "none", lth_log::log_level::none },
            { "trace", lth_log::log_level::trace },
            { "debug", lth_log::log_level::debug },
            { "info", lth_log::log_level::info },
            { "warning", lth_log::log_level::warning },
            { "error", lth_log::log_level::error },
            { "fatal", lth_log::log_level::fatal }
        };
        lvl = option_to_log_level.at(loglevel_);
    } catch (const std::out_of_range& e) {
        throw Configuration::Error {
            lth_loc::format("invalid log level: '{1}'", loglevel_) };
    }

    // Configure logging for pxp-agent
    lth_log::setup_logging(*stream);
    lth_log::set_level(lvl);

#ifdef DEV_LOG_COLOR
    // Enable colorozation anyway (development setting - it helps
    // debugging PXP message workflow, but it will add useless shell
    // control sequences to log entries on file)
    lth_log::set_colorization(true);
    bool force_colorization = true;
#else
    bool force_colorization = false;
#endif  // DEV_LOG_COLOR

    // Configure logging for cpp-pcp-client
    PCPClient::Util::setupLogging(*stream, force_colorization, loglevel_);

    LOG_DEBUG("Logging configured");

    if (!log_on_stdout) {
        // Configure platform-specific things for file logging
        // NB: we do that after setting up lth_log in order to log in
        //     case of failure
        configure_platform_file_logging();
    }
}

void Configuration::validate()
{
    validateAndNormalizeWebsocketSettings();
    validateAndNormalizeOtherSettings();
    valid_ = true;
}

const Configuration::Agent& Configuration::getAgentConfiguration() const
{
    assert(valid_);
    return agent_configuration_;
}

void Configuration::reopenLogfile() const
{
    if (!logfile_.empty() && logfile_ != "-") {
        try {
            logfile_fstream_.close();
        } catch (const std::exception& e) {
            LOG_DEBUG("Failed to close logfile stream; already closed?");
        }
        try {
            logfile_fstream_.open(logfile_.c_str(), std::ios_base::app);
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to open logfile stream");
        }
    }
}

//
// Private interface
//

Configuration::Configuration() : valid_ { false },
                                 defaults_ {},
                                 config_file_ { "" },
                                 agent_configuration_ {},
                                 logfile_ { "" },
                                 loglevel_ { "" },
                                 foreground_ { false },
                                 logfile_fstream_ {}
{
    defineDefaultValues();
}

static void validate_wss(std::string const& uri, std::string const& name)
{
    if (uri.find("wss://") != 0)
        throw Configuration::Error {
            lth_loc::format("{1} value \"{2}\" must start with wss://", name, uri) };
}

// Helper function
std::string check_and_expand_ssl_cert(const std::string& cert_name)
{
    auto c = HW::GetFlag<std::string>(cert_name);
    if (c.empty())
        throw Configuration::Error {
            lth_loc::format("{1} value must be defined", cert_name) };

    c = lth_file::tilde_expand(c);
    if (!fs::exists(c))
        throw Configuration::Error {
            lth_loc::format("{1} file '{2}' not found", cert_name, c) };

    if (!lth_file::file_readable(c))
        throw Configuration::Error {
            lth_loc::format("{1} file '{2}' not readable", cert_name, c) };

    return c;
}

void Configuration::defineDefaultValues()
{
    agent_configuration_.client_type = AGENT_CLIENT_TYPE;

    defaults_.insert(
        Option { "config-file",
                 Base_ptr { new Entry<std::string>(
                    "config-file",
                    "",
                    lth_loc::format("Config file, default: {1}", DEFAULT_CONFIG_FILE),
                    Types::String,
                    DEFAULT_CONFIG_FILE,
                    [&](std::string &s) {
                        config_file_ = lth_file::tilde_expand(s);
                    }) } });

    defaults_.insert(
        Option { "broker-ws-uri",
                 Base_ptr { new Entry<std::string>(
                    "broker-ws-uri",
                    "",
                    lth_loc::translate("WebSocket URI of the PCP broker"),
                    Types::String,
                    "",
                    [&](std::string &uri) {
                        if (!uri.empty()) {
                            if (!agent_configuration_.broker_ws_uris.empty())
                                throw Configuration::Error {
                                    lth_loc::translate("broker-ws-uri and broker-ws-uris cannot both be defined") };

                            validate_wss("broker-ws-uri", uri);
                            agent_configuration_.broker_ws_uris.push_back(uri);
                        }
                    }) } });

    defaults_.insert(
        Option { "broker-ws-uris",
                 Base_ptr { new Entry<std::vector<std::string>>(
                    "broker-ws-uris",
                    "",
                    lth_loc::translate("List of WebSocket URIs of PCP brokers "
                                       "(cannot be used with broker-ws-uri)"),
                    Types::MultiString,
                    {},
                    [&](std::vector<std::string> &vals) {
                        if (!agent_configuration_.broker_ws_uris.empty())
                            throw Configuration::Error {
                                lth_loc::translate("broker-ws-uri and broker-ws-uris cannot both be defined") };

                        for (auto &uri : vals) {
                            validate_wss("broker-ws-uris", uri);
                        }

                        if (!vals.empty()) {
                            agent_configuration_.broker_ws_uris = vals;
                        }
                    }) } });

    defaults_.insert(
        Option { "connection-timeout",
                 Base_ptr { new Entry<int>(
                    "connection-timeout",
                    "",
                    lth_loc::translate("Timeout (in seconds) for starting the "
                                       "WebSocket handshake, default: 5 s"),
                    Types::Int,
                    5,
                    [&](int &i) {
                        agent_configuration_.ws_connection_timeout_ms = i * 1000;
                    }) } });

    // Hidden option: number of ping/pong timeouts to allow before
    // disconnecting, default: 2
    defaults_.insert(
        Option { "allowed-keepalive-timeouts",
                 Base_ptr { new Entry<int>(
                    "allowed-keepalive-timeouts",
                    "",
                    "<hidden>",
                    Types::Int,
                    2,
                    [&](int &i) {
                        agent_configuration_.allowed_keepalive_timeouts = static_cast<uint32_t>(i);
                    }) } });

    // Hidden option: PCP Association timeout, default: 15 s
    defaults_.insert(
        Option { "association-timeout",
                 Base_ptr { new Entry<int>(
                    "association-timeout",
                    "",
                    "<hidden>",
                    Types::Int,
                    15,
                    [&](int &i) {
                        if (i < 0)
                            throw Configuration::Error {
                                lth_loc::translate("association-timeout must be positive") };
                        agent_configuration_.association_timeout_s = static_cast<uint32_t>(i);
                    }) } });

    // Hidden option: TTL of the PCP Association request, default: 10 s
    defaults_.insert(
        Option { "association-request-ttl",
                 Base_ptr { new Entry<int>(
                    "association-request-ttl",
                    "",
                    "<hidden>",
                    Types::Int,
                    10,
                    [&](int &i) {
                        if (i < 0)
                            throw Configuration::Error {
                                lth_loc::translate("association-request-ttl must be positive") };
                        agent_configuration_.association_request_ttl_s = static_cast<uint32_t>(i);
                    }) } });

    // Hidden option: TTL of the PCP messages, default: 5 s
    defaults_.insert(
        Option { "pcp-message-ttl",
                 Base_ptr { new Entry<int>(
                    "pcp-message-ttl",
                    "",
                    "<hidden>",
                    Types::Int,
                    5,
                    [&](int &i) {
                        if (i < 0)
                            throw Configuration::Error {
                                lth_loc::translate("association-request-ttl must be positive") };
                        agent_configuration_.pcp_message_ttl_s = static_cast<uint32_t>(i);
                    }) } });

    defaults_.insert(
        Option { "ssl-ca-cert",
                 Base_ptr { new Entry<std::string>(
                    "ssl-ca-cert",
                    "",
                    lth_loc::translate("SSL CA certificate"),
                    Types::String,
                    "",
                    [&](std::string &s) {
                        if (!s.empty())
                            agent_configuration_.ca = check_and_expand_ssl_cert(s);
                    }) } });

    defaults_.insert(
        Option { "ssl-cert",
                 Base_ptr { new Entry<std::string>(
                    "ssl-cert",
                    "",
                    lth_loc::translate("pxp-agent SSL certificate"),
                    Types::String,
                    "",
                    [&](std::string &s) {
                        if (!s.empty())
                            agent_configuration_.crt = check_and_expand_ssl_cert(s);
                    }) } });

    defaults_.insert(
        Option { "ssl-key",
                 Base_ptr { new Entry<std::string>(
                    "ssl-key",
                    "",
                    lth_loc::translate("pxp-agent private SSL key"),
                    Types::String,
                    "",
                    [&](std::string &s) {
                        if (!s.empty())
                            agent_configuration_.key = check_and_expand_ssl_cert(s);
                    }) } });

    defaults_.insert(
        Option { "logfile",
                 Base_ptr { new Entry<std::string>(
                    "logfile",
                    "",
                    lth_loc::format("Log file, default: {1}", DEFAULT_LOG_FILE),
                    Types::String,
                    DEFAULT_LOG_FILE,
                    [&](std::string &s) {
                        logfile_ = s;
                    }) } });

    defaults_.insert(
        Option { "loglevel",
                 Base_ptr { new Entry<std::string>(
                    "loglevel",
                    "",
                    lth_loc::translate("Valid options are 'none', 'trace', "
                                       "'debug', 'info','warning', 'error' and "
                                       "'fatal'. Defaults to 'info'"),
                    Types::String,
                    "info",
                    [&](std::string &s) {
                        loglevel_ = s;
                    }) } });

    defaults_.insert(
        Option { "modules-dir",
                 Base_ptr { new Entry<std::string>(
                    "modules-dir",
                    "",
                    lth_loc::format("Modules directory, default"
#ifdef _WIN32
                                    " (relative to the pxp-agent.exe path)"
#endif
                                    ": {1}", DEFAULT_MODULES_DIR),
                    Types::String,
                    DEFAULT_MODULES_DIR,
                    [&](std::string &s) {
                        agent_configuration_.modules_dir = s;
                    }) } });

    defaults_.insert(
        Option { "modules-config-dir",
                 Base_ptr { new Entry<std::string>(
                    "modules-config-dir",
                    "",
                    lth_loc::format("Module config files directory, default: {1}",
                                    DEFAULT_MODULES_CONF_DIR),
                    Types::String,
                    DEFAULT_MODULES_CONF_DIR,
                    [&](std::string &s) {
                        agent_configuration_.modules_config_dir = s;
                    }) } });

    defaults_.insert(
        Option { "spool-dir",
                 Base_ptr { new Entry<std::string>(
                    "spool-dir",
                    "",
                    lth_loc::format("Spool action results directory, default: {1}",
                                    DEFAULT_SPOOL_DIR),
                    Types::String,
                    DEFAULT_SPOOL_DIR,
                    [&](std::string &s) {
                        agent_configuration_.spool_dir = s;
                    }) } });

    defaults_.insert(
        Option { "spool-dir-purge-ttl",
                 Base_ptr { new Entry<std::string>(
                    "spool-dir-purge-ttl",
                    "",
                    lth_loc::format("TTL for action results before being deleted, "
                                    "default: '{1}' (days)",
                                    DEFAULT_SPOOL_DIR_PURGE_TTL),
                    Types::String,
                    DEFAULT_SPOOL_DIR_PURGE_TTL,
                    [&](std::string &s) {
                        try {
                            Timestamp t(s);
                        } catch (const Timestamp::Error& e) {
                            throw Configuration::Error {
                                lth_loc::format("invalid spool-dir-purge-ttl: {1}", e.what()) };
                        }
                        agent_configuration_.spool_dir_purge_ttl = s;
                    }) } });

    defaults_.insert(
        Option { "foreground",
                 Base_ptr { new Entry<bool>(
                    "foreground",
                    "",
                    lth_loc::translate("Don't daemonize, default: false"),
                    Types::Bool,
                    false,
                    [&](bool &b) {
                        foreground_ = b;
                    }) } });

#ifndef _WIN32
    // NOTE(ale): we don't daemonize on Windows; we rely NSSM to start
    // the pxp-agent service and on CreateMutexA() to avoid multiple
    // pxp-agent instances at once
    defaults_.insert(
        Option { "pidfile",
                 Base_ptr { new Entry<std::string>(
                    "pidfile",
                    "",
                    lth_loc::format("PID file path, default: {1}", DEFAULT_PID_FILE),
                    Types::String,
                    DEFAULT_PID_FILE,
                    [&](std::string &s) {
                        pidfile_ = s;
                    }) } });
#endif
}

void Configuration::setDefaultValues()
{
    for (auto opt_idx = defaults_.get<Option::ByInsertion>().begin();
         opt_idx != defaults_.get<Option::ByInsertion>().end();
         ++opt_idx) {
        std::string flag_names { opt_idx->ptr->name };

        if (!opt_idx->ptr->aliases.empty()) {
            flag_names += " " + opt_idx->ptr->aliases;
        }

        switch (opt_idx->ptr->type) {
            case Types::Int:
                {
                    Entry<int>* entry_ptr = (Entry<int>*) opt_idx->ptr.get();
                    HW::DefineGlobalFlag<int>(flag_names, entry_ptr->help,
                                              entry_ptr->value, entry_ptr->setter);
                }
                break;
            case Types::Bool:
                {
                    Entry<bool>* entry_ptr = (Entry<bool>*) opt_idx->ptr.get();
                    HW::DefineGlobalFlag<bool>(flag_names, entry_ptr->help,
                                               entry_ptr->value, entry_ptr->setter);
                }
                break;
            case Types::Double:
                {
                    Entry<double>* entry_ptr = (Entry<double>*) opt_idx->ptr.get();
                    HW::DefineGlobalFlag<double>(flag_names, entry_ptr->help,
                                                 entry_ptr->value, entry_ptr->setter);
                }
                break;
            case Types::String:
                {
                    Entry<std::string>* entry_ptr = (Entry<std::string>*) opt_idx->ptr.get();
                    HW::DefineGlobalFlag<std::string>(flag_names, entry_ptr->help,
                                                      entry_ptr->value, entry_ptr->setter);
                }
                break;
            case Types::MultiString:
                // Not supported by Horsewhisperer.
                break;
        }
    }
}

void Configuration::parseConfigFile()
{
    if (!lth_file::file_readable(config_file_))
        return;

    lth_jc::JsonContainer config_json;

    try {
        config_json = lth_jc::JsonContainer(lth_file::read(config_file_));
    } catch (lth_jc::data_parse_error& e) {
        throw Configuration::Error {
            lth_loc::translate("cannot parse config file; invalid JSON") };
    }

    if (config_json.type() != lth_jc::DataType::Object)
        throw Configuration::Error { "invalid config file content; not a "
                                     "JSON object" };

    auto check_key_type =
        [&config_json] (const std::string& key,
                        const std::string& type_str,
                        const lth_jc::DataType& type) -> void
        {
            if (config_json.type(key) != type)
                throw Configuration::Error {
                    lth_loc::format("field '{1}' must be of type {2}",
                                    key, type_str) };
        };

    for (const auto& key : config_json.keys()) {
        const auto& opt_idx = defaults_.get<Option::ByName>().find(key);

        if (opt_idx == defaults_.get<Option::ByName>().end())
            throw Configuration::Error {
                lth_loc::format("field '{1}' is not a valid configuration variable",
                                key) };

        switch (opt_idx->ptr->type) {
            case Types::Int:
                {
                    check_key_type(key, "Integer", lth_jc::DataType::Int);
                    Entry<int>* entry_ptr = (Entry<int>*) opt_idx->ptr.get();
                    auto val = config_json.get<int>(key);
                    entry_ptr->setter(val);
                }
                break;
            case Types::Bool:
                {
                    check_key_type(key, "Bool", lth_jc::DataType::Bool);
                    Entry<bool>* entry_ptr = (Entry<bool>*) opt_idx->ptr.get();
                    auto val = config_json.get<bool>(key);
                    entry_ptr->setter(val);
                }
                break;
            case Types::Double:
                {
                    check_key_type(key, "Double", lth_jc::DataType::Double);
                    Entry<double>* entry_ptr = (Entry<double>*) opt_idx->ptr.get();
                    auto val = config_json.get<double>(key);
                    entry_ptr->setter(val);
                }
                break;
            case Types::String:
                {
                    check_key_type(key, "String", lth_jc::DataType::String);
                    Entry<std::string>* entry_ptr = (Entry<std::string>*) opt_idx->ptr.get();
                    auto val = config_json.get<std::string>(key);
                    entry_ptr->setter(val);
                }
                break;
            case Types::MultiString:
                {
                    check_key_type(key, "Array", lth_jc::DataType::Array);
                    Entry<std::vector<std::string>>* entry_ptr = (Entry<std::vector<std::string>>*) opt_idx->ptr.get();
                    auto val = config_json.get<std::vector<std::string>>(key);
                    entry_ptr->setter(val);
                }
                break;
        }
    }
}

void Configuration::validateAndNormalizeWebsocketSettings()
{
    if (agent_configuration_.broker_ws_uris.empty())
        throw Configuration::Error {
            lth_loc::translate("broker-ws-uris must be defined") };

    // Ensure client certs are good
    try {
        PCPClient::getCommonNameFromCert(agent_configuration_.crt);
        PCPClient::validatePrivateKeyCertPair(agent_configuration_.key, agent_configuration_.crt);
    } catch (const PCPClient::connection_config_error& e) {
        throw Configuration::Error { e.what() };
    }
}

// Helper function
void check_and_create_dir(const fs::path& dir_path,
                          const std::string& opt,
                          const bool& create)
{
    if (!fs::exists(dir_path)) {
        if (create) {
            try {
                LOG_INFO("Creating the {1} '{2}'", opt, dir_path.string());
                fs::create_directories(dir_path);
            } catch (const std::exception& e) {
                LOG_DEBUG("Failed to create the {1} '{2}': {3}",
                          opt, dir_path.string(), e.what());
                throw Configuration::Error {
                    lth_loc::format("failed to create the {1} '{2}'",
                                    opt, dir_path.string()) };
            }
        } else {
            throw Configuration::Error {
                lth_loc::format("the {1} '{2}' does not exist",
                                opt, dir_path.string()) };
        }
    } else if (!fs::is_directory(dir_path)) {
        throw Configuration::Error {
                lth_loc::format("the {1} '{2}' is not a directory",
                                opt, dir_path.string()) };
    }
}

void Configuration::validateAndNormalizeOtherSettings()
{
    // Normalize and check modules' directories
    std::vector<std::string> options { "modules-dir", "modules-config-dir" };

    for (const auto& option : options) {
        auto val = HW::GetFlag<std::string>(option);

        if (val.empty())
            continue;

        fs::path val_path { lth_file::tilde_expand(val) };
        check_and_create_dir(val_path, val, false);
        HW::SetFlag<std::string>(option, val_path.string());
    }

    // Create the spool-dir if needed and ensure we can write in it
    const auto spool_dir = HW::GetFlag<std::string>("spool-dir");

    if (spool_dir.empty())
        throw Configuration::Error {
            lth_loc::translate("spool-dir must be defined") };

    fs::path spool_dir_path { lth_file::tilde_expand(spool_dir) };
    check_and_create_dir(spool_dir_path, "spool-dir", true);
    fs::path tmp_path;

    do {
        tmp_path = spool_dir_path / lth_util::get_UUID();
    } while (fs::exists(tmp_path));

    bool is_writable { false };
    try {
        if (fs::create_directories(tmp_path)) {
            is_writable = true;
            fs::remove_all(tmp_path);
        }
    } catch (const std::exception& e) {
        LOG_DEBUG("Failed to create the test dir in spool path '{1}' during"
                  "configuration validation: {2}",
                  spool_dir_path.string(), e.what());
    }

    if (!is_writable)
        throw Configuration::Error {
            lth_loc::format("the spool-dir '{1}' is not writable",
                            spool_dir_path.string()) };

    HW::SetFlag<std::string>("spool-dir", spool_dir_path.string());

#ifndef _WIN32
    if (!HW::GetFlag<bool>("foreground")) {
        auto pid_file = lth_file::tilde_expand(HW::GetFlag<std::string>("pidfile"));

        if (fs::exists(pid_file) && !(fs::is_regular_file(pid_file)))
            throw Configuration::Error {
                lth_loc::format("the PID file '{1}' is not a regular file", pid_file) };

        auto pid_dir = fs::path(pid_file).parent_path().string();

        // We know that, on Solaris, the /var/run when gets cleaned up
        // at reboot; daemonization assumes that the PID file
        // directory exists. So, if we're using the default PID
        // directory, ensure it exists (PCP-297)
        if (pid_dir == "/var/run/puppetlabs" && !fs::exists(pid_dir)) {
            try {
                LOG_DEBUG("Creating the PID file directory '{1}'", pid_dir);
                fs::create_directories(pid_dir);
            } catch (const std::exception& e) {
                LOG_DEBUG("Failed to create '{1}' directory: {2}", pid_dir, e.what());
                throw Configuration::Error {
                    lth_loc::translate("failed to create the PID file directory") };
            }
        }

        if (fs::exists(pid_dir)) {
            if (!fs::is_directory(pid_dir))
                throw Configuration::Error {
                    lth_loc::format("'{1}' is not a directory", pid_dir) };
        } else {
            throw Configuration::Error {
                lth_loc::format("the PID directory '{1}' does not exist; "
                                "cannot create the PID file", pid_dir) };
        }

        HW::SetFlag<std::string>("pidfile", pid_file);
    }
#endif
}

std::string Configuration::getInvalidFlagError(const std::string& flagname)
{
    return lth_loc::format("invalid value for {1}", flagname);
}

std::string Configuration::getUnknownFlagError(const std::string& flagname)
{
    return lth_loc::format("unknown flag name: {1}", flagname);
}

void Configuration::checkValidForSetting()
{
    if (!valid_)
        throw Configuration::Error {
            lth_loc::translate("cannot set configuration value until "
                               "configuration is validated") };
}

}  // namespace PXPAgent

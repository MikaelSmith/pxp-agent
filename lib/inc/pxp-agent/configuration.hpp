#ifndef SRC_CONFIGURATION_H_
#define SRC_CONFIGURATION_H_

#include <horsewhisperer/horsewhisperer.h>

#include <boost/nowide/fstream.hpp>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>

#include <memory>
#include <stdexcept>
#include <cstdint>

namespace PXPAgent {

//
// Tokens
//

extern const std::string DEFAULT_SPOOL_DIR;     // used by unit tests

//
// Types
//
enum class Types { Bool, Int, Double, String, MultiString };

struct EntryBase
{
    // Config option name
    // HERE: must match one of the flag names and config file option
    std::string name;
    // CLI option aliases (e.g. --enable-transmogrification -t)
    std::string aliases;
    // Help string to be displayed by --help flag
    std::string help;
    // Value type
    Types type;

    EntryBase(std::string _name, std::string _aliases, std::string _help, Types _type)
            : name { std::move(_name) },
              aliases { std::move(_aliases) },
              help { std::move(_help) },
              type { std::move(_type) } {
    }
};

template <typename T>
struct Entry : EntryBase
{
    // Default value
    T value;
    // Function for storing the value in a Configuration::Agent
    std::function<void(T&)> setter;

    Entry<T>(std::string _name, std::string _aliases, std::string _help, Types _type,
             T _value, std::function<void(T&)> _setter)
            : EntryBase { std::move(_name), std::move(_aliases), std::move(_help), std::move(_type) },
              value { std::move(_value) }, setter { std::move(_setter) } {
        // Initialize from the default value.
        setter(value);
    }
};

using Base_ptr = std::unique_ptr<EntryBase>;

// Use a boost::multi_index container to allow accessing default
// options by key (option name) and insertion order
struct Option {
    std::string name;
    Base_ptr ptr;

    // boost::multi_index tag: retrieve option by name, map-style
    // NB: any type can be used as a multi-index tag
    struct ByName {};

    // boost::multi_index tag: retrieve option by insertion order,
    // vector-style
    struct ByInsertion {};
};

typedef boost::multi_index::multi_index_container<
    Option,
    boost::multi_index::indexed_by<
        boost::multi_index::hashed_unique<
            boost::multi_index::tag<Option::ByName>,
            boost::multi_index::member<Option,
                                       std::string,
                                       &Option::name>
        >,
        boost::multi_index::random_access<
            boost::multi_index::tag<Option::ByInsertion>
        >
    >
> Options;

//
// Platform-specific interface
//

/// Perform the platform specific configuration steps for setting up
/// the pxp-agent logging to file.
/// Throw a Configuration::Error in case of failure.
void configure_platform_file_logging();

//
// Configuration (singleton)
//

class Configuration
{
  public:
    struct Error : public std::runtime_error
    {
        explicit Error(std::string const& msg) : std::runtime_error(msg) {}
    };

    static Configuration& Instance()
    {
        static Configuration instance {};
        return instance;
    }

    struct Agent
    {
        std::string modules_dir;
        std::vector<std::string> broker_ws_uris;
        std::string ca;
        std::string crt;
        std::string key;
        std::string spool_dir;
        std::string spool_dir_purge_ttl;
        std::string modules_config_dir;
        std::string client_type;
        long ws_connection_timeout_ms;
        uint32_t association_timeout_s;
        uint32_t association_request_ttl_s;
        uint32_t pcp_message_ttl_s;
        uint32_t allowed_keepalive_timeouts;
    };

    /// Reset the HorseWhisperer singleton.
    /// Set the configuration entries to their default values and the
    /// specified start function that will be configured as the
    /// unique HorseWhisperer action for pxp-agent.
    /// Initialize the boost filesystem locale.
    void initialize(std::function<int(std::vector<std::string>)> start_function);

    /// Parse the command line arguments and, if specified, the
    /// configuration file.
    /// Return a HorseWhisperer::ParseResult value indicating the
    /// parsing outcome (refer to HorseWhisperer).
    /// Throw a HorseWhisperer::flag_validation_error in case such
    /// exception is thrown by a flag validation callback.
    /// Throw a Configuration::Error: if it fails to parse the CLI
    /// arguments; if the specified config file cannot be parsed or
    /// has any invalid JSON entry.
    HorseWhisperer::ParseResult parseOptions(int argc, char *argv[]);

    /// Validate logging configuration options and enable logging.
    /// Throw a Configuration::Error: in case of invalid the specified
    /// log file is in a non-esixtent directory.
    /// Other execeptions are propagated.
    void setupLogging();

    /// Ensure all required values are valid. If necessary, expand
    /// file paths to the expected format.
    /// Throw a Configuration::Error in case an option is set to an
    /// invalid value.
    void validate();

    /// Return an object containing all agent configuration options
    const Agent& getAgentConfiguration() const;

    /// Try to close the log file stream,  then try to open the log
    /// file in append mode and associate it to the log file stream.
    /// All possible exceptions will be filtered.
    void reopenLogfile() const;

#ifndef _WIN32
    /// Get the pid lock file name.
    std::string const& pidfile() const { return pidfile_; }
#endif

    /// Get whether running in foreground mode.
    bool foreground() const { return foreground_; }

  private:
    // Whether the Configuration singleton has successfully validated
    // all options specified by both CLI and file
    bool valid_;

    // Stores options with relative default values
    Options defaults_;

    // Path to the pxp-agent configuration file
    std::string config_file_;

    // Function that starts the pxp-agent service
    std::function<int(std::vector<std::string>)> start_function_;

    // Cache for agent configuration parameters
    mutable Agent agent_configuration_;

    // Path to the logfile
    std::string logfile_;
    std::string loglevel_;

    // Service options
    bool foreground_;
#ifndef _WIN32
    std::string pidfile_;
#endif

    // Stream abstraction object for the logfile
    mutable boost::nowide::ofstream logfile_fstream_;

    // Defines the default values
    Configuration();

    void defineDefaultValues();
    void setDefaultValues();
    void setStartAction();
    void parseConfigFile();
    void validateAndNormalizeWebsocketSettings();
    void validateAndNormalizeOtherSettings();
    void setAgentConfiguration();
    std::string getInvalidFlagError(const std::string& flagname);
    std::string getUnknownFlagError(const std::string& flagname);
    void checkValidForSetting();
};

}  // namespace PXPAgent

#endif  // SRC_CONFIGURATION_H_

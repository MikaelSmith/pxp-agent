#ifndef SRC_AGENT_RESULTS_STORAGE_HPP_
#define SRC_AGENT_RESULTS_STORAGE_HPP_

#include <pxp-agent/action_output.hpp>

#include <leatherman/json_container/json_container.hpp>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <vector>
#include <string>
#include <stdexcept>
#include <functional>  // std::function

namespace PXPAgent {

// NOTE(ale): possible execptions thrown while inspecting files are
// propagated by ResultsStorage methods (more specifically, errors
// raised by boost::filesystem::exists() are not filtered).
class ResultsStorage {
  public:
    struct Error : public std::runtime_error {
        explicit Error(std::string const& msg) : std::runtime_error(msg) {}
    };

    ResultsStorage() = delete;
    ResultsStorage(const std::string& spool_dir);
    ResultsStorage(const ResultsStorage&) = delete;
    ResultsStorage& operator=(const ResultsStorage&) = delete;

    // Returns true if a results directory for the specified
    // transaction exists, false otherwise.
    bool find(const std::string& transaction_id);

    // Initializes the metadata file for the specified transaction.
    // Creates the results directory if necessary.
    // Throws an Error in case it fails to create the directory or
    // in case it fails to write to file.
    void initializeMetadataFile(
        const std::string& transaction_id,
        const leatherman::json_container::JsonContainer& metadata);

    // Updates the metadata file.
    // Throws an Error in case there's no results directory for the
    // specified transaction or in case it fails to write to file.
    void updateMetadataFile(
        const std::string& transaction_id,
        const leatherman::json_container::JsonContainer& metadata);

    // Returns the action metadata specified by the transaction.
    // Throws an Error in case:
    //  - the metadata file does not exist;
    //  - the function fails to read the content of the metadata file;
    //  - the content of the metadata file is not valid JSON;
    //  - the metadata does not comply with its JSON schema.
    leatherman::json_container::JsonContainer
    getActionMetadata(const std::string& transaction_id);

    // Returns true if the PID file for the specified transaction
    // exists, false otherwise.
    bool pidFileExists(const std::string& transaction_id);

    // Returns the PID.
    // Throws an error in case:
    //  - there's no PID file for the specified transaction;
    //  - it fails to read a valid integer PID.
    int getPID(const std::string& transaction_id);

    // Returns true if the exitcode file for the specified transaction
    // exists, false otherwise.
    bool outputIsReady(const std::string& transaction_id);

    // Returns the output of the action specified by the transaction.
    // Throws an Error in case:
    //  - it the stdout file exist, but the function fails to read it;
    //  - it fails to read a valid integer exit code.
    ActionOutput getOutput(const std::string& transaction_id);

    // Same as above, but does not retrieve the exit code from file.
    ActionOutput getOutput(const std::string& transaction_id,
                           int exitcode);

    // Updates the index for a transactions streaming output.
    void updateStreamIndex(const std::string& transaction_id, size_t idx);

    // Delete the streaming index file.
    void clearStreamIndex(const std::string& transaction_id);

    // Reads the index for a transactions streaming output.
    size_t getStreamIndex(const std::string& transaction_id);

    // Read all contents from streaming output after the idx.
    // Returns the new idx and any content read.
    std::tuple<size_t, std::string> readLatest(const std::string& transaction_id, size_t idx);

    // Cleans up the spool directory by removing the results
    // directories that are older than the specified ttl and skipping
    // the directories related to ongoing tasks.
    // This function is not thread safe.
    // If a purge_callback is not specified, the boost filesystem's
    // remove_all() will be used.
    unsigned int purge(
        const std::string& ttl,
        const std::vector<std::string>& ongoing_transactions,
        std::function<void(const std::string& dir_path)> purge_callback = nullptr);

  private:
    const boost::filesystem::path spool_dir_path_;

    ActionOutput getOutput_(const std::string& transaction_id,
                            bool get_exitcode);
};

}  // namespace PXPAgent

#endif  // SRC_AGENT_RESULTS_STORAGE_HPP_

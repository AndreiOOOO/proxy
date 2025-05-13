#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include <string>
#include <unordered_set>
#include <mutex>

class packet_filter {
public:
    void add_process(std::string process);
    bool check_process(std::string process);

private:
    std::unordered_set<std::string> filtered_processes;
    std::mutex mtx;
};

#endif // PACKET_FILTER_H
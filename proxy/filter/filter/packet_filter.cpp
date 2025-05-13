#include "packet_filter.h"
#include <algorithm>

void packet_filter::add_process(std::string process) {
    std::lock_guard<std::mutex> lock(mtx);
    std::transform(process.begin(), process.end(), process.begin(), ::tolower);
    filtered_processes.insert(process);
}

bool packet_filter::check_process(std::string process) {
    std::lock_guard<std::mutex> lock(mtx);
    std::transform(process.begin(), process.end(), process.begin(), ::tolower);
    return filtered_processes.find(process) != filtered_processes.end();
}
#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <queue>
#include <map>


class filter_settings {
public:
    struct filter_entry {
        std::string process_name;
    };

    struct forward_entry {
        uint32_t id;
        uint32_t address;
        uint16_t port;
        std::vector<filter_entry> filter_entries;

        bool initialized = false;
    };

    forward_entry* get_forward_entry(uint32_t entry_id) {
        auto it = forward_entries_.find(entry_id);
        if (it != forward_entries_.end()) {
            return &it->second;
        }
        return nullptr;
    }

    forward_entry* get_foward_entry(const std::string& process_name, uint8_t protocol, uint32_t sa, uint16_t sp, uint32_t da, uint16_t dp) {
        for (auto& entry : forward_entries_) {
            for (auto& filter_entry : entry.second.filter_entries) {
                if (filter_entry.process_name == process_name) {
                    return &entry.second;
                }
            }
        }
        return nullptr;
    }

    std::unordered_map<uint32_t, forward_entry> forward_entries_;
};
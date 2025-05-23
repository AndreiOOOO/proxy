#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <queue>
#include <map>

#include "..\\ip_convert.h"


class filter_settings {
public:
    struct filter_entry {
        std::string process_name;
    };

    filter_settings(){
        auto& _test = forward_entries_[0];
        _test.port = 5000;
        _test.address = ip_to_uint32("127.0.0.1");
        _test.id = 1;

        filter_entry _entry;
        _entry.process_name = "tibia.exe";
        _test.filter_entries.push_back(_entry);
        _entry.process_name = "tibia-1746908820.exe";
        _test.filter_entries.push_back(_entry);

        forward_entries_[_test.id] = _test;
    }
  

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
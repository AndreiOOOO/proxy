#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <queue>
#include <map>
        

struct relation_map_entry_t {
    bool _null = true;
    uint32_t source_id;
    uint32_t relation_id;
    uint8_t proto;
    std::string process_name;

    uint32_t foward_id;
};

struct relation_map_t {
    void add(uint32_t source_id, uint32_t relation_id, uint8_t proto, std::string pname) {
        if (relation_mapping.find(source_id) == relation_mapping.end()) {
            relation_map_entry_t entry = { false, source_id, relation_id , proto, pname };
            relation_mapping[source_id] = entry;
        }
    }

    relation_map_entry_t* get(uint32_t source_id) {
        auto it = relation_mapping.find(source_id);
        if (it != relation_mapping.end()) {
            return &it->second;
        }
        return nullptr;
    }

    relation_map_entry_t* get_by_remaped_id(uint32_t remaped_id) {
        for (auto& pair : relation_mapping) {
            if (pair.second.relation_id == remaped_id) {
                return &pair.second;
            }
        }
        return nullptr;
    }

private:
    std::map<uint32_t, relation_map_entry_t> relation_mapping;
};
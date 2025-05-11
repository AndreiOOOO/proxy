#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <queue>
#include <map>

extern void filter_any_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> handler);
extern void filter_any_server_add_data(uint32_t any_server_id, const std::string& data, std::string protocol, std::string from_address, unsigned short from_port);
extern bool filter_any_get_original_relation(uint32_t id, std::string proto, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp);
//extern void internet_connector_async_send(uint16_t source_id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data);
//extern void internet_connector_async_receive(std::function<void(uint16_t, uint8_t, std::shared_ptr<std::string>)> handler);

extern void internet_connector_async_send(uint32_t id, uint8_t proto, uint32_t dest_address,
    uint16_t dest_port, std::shared_ptr<std::string> data);

extern void internet_connector_async_receive(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler);

struct any_relation_map_entry_t {
    bool _null = true;
    uint32_t source_id;
    uint32_t relation_id;
    uint8_t proto;
};

struct any_relation_map_t {
    void add(uint32_t source_id, uint32_t relation_id, uint8_t proto) {
        if (relation_mapping.find(source_id) == relation_mapping.end()) {
            any_relation_map_entry_t entry = { false, source_id, relation_id , proto };
            relation_mapping[source_id] = entry;
        }
    }

    any_relation_map_entry_t get(uint32_t source_id) {
        auto it = relation_mapping.find(source_id);
        if (it != relation_mapping.end()) {
            return it->second;
        }
        return any_relation_map_entry_t();
    }

    any_relation_map_entry_t get_by_remaped_id(uint32_t remaped_id) {
        for (auto& pair : relation_mapping) {
            if (pair.second.relation_id == remaped_id) {
                return pair.second;
            }
        }
        return any_relation_map_entry_t();
    }

private:
    std::map<uint32_t, any_relation_map_entry_t> relation_mapping;
};

any_relation_map_t relation_map;

void on_local_data(uint32_t source_id, std::shared_ptr<std::string> data, std::string protocol) {
    uint32_t sa, da;
    uint16_t sp, dp;
    // get original endpoint relations
    if (filter_any_get_original_relation(source_id, protocol, sa, sp, da, dp)) {
        uint8_t proto_value = (protocol == "tcp") ? 6 : 17; // 6 para TCP, 17 para UDP
        relation_map.add(source_id, sp, proto_value); // mapeia o source_id para o relation_id
        internet_connector_async_send(sp, proto_value, da, dp, data);
    }
}

void on_internet_data(uint32_t internet_id, std::shared_ptr<std::string> data) {
    auto _f = relation_map.get_by_remaped_id(internet_id);
    if (!_f._null) {
        std::string protocol = (_f.proto == 6) ? "tcp" : "udp";
        filter_any_server_add_data(_f.source_id, *data, protocol, "", 0);
    }
    else {
        // lidar com o caso em que o source_id não está mapeado
    }
}

void core_run() {
    filter_any_server_async_recv(on_local_data);
    internet_connector_async_receive(on_internet_data);
}

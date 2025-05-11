#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <queue>
#include <map>

extern void filter_any_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> handler);
extern void filter_any_server_add_data(uint32_t any_server_id, const std::string& data, std::string protocol, std::string from_address, unsigned short from_port);
extern bool filter_any_get_original_relation(uint32_t id, std::string proto, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp);
extern void internet_connector_async_send(uint16_t source_id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data);
extern void internet_connector_async_receive(std::function<void(uint16_t, uint8_t, std::shared_ptr<std::string>)> handler);

struct any_relation_map_entry_t {
    uint32_t relation_id;
};

struct any_relation_map_t {
    void add(uint16_t source_id, uint32_t relation_id) {
        any_relation_map_entry_t entry = { relation_id };
        relation_mapping[source_id] = entry;
    }

    bool get(uint16_t source_id, uint32_t& relation_id) {
        auto it = relation_mapping.find(source_id);
        if (it != relation_mapping.end()) {
            relation_id = it->second.relation_id;
            return true;
        }
        return false;
    }

private:
    std::map<uint16_t, any_relation_map_entry_t> relation_mapping;
};

any_relation_map_t relation_map;

void on_local_data(uint32_t relation_id, std::shared_ptr<std::string> data, std::string protocol) {
    uint32_t sa, da;
    uint16_t sp, dp;
    // get original endpoint relations
    if (filter_any_get_original_relation(relation_id, protocol, sa, sp, da, dp)) {
        uint8_t proto_value = (protocol == "tcp") ? 6 : 17; // 6 para TCP, 17 para UDP
        relation_map.add(sp, relation_id); // mapeia o source_id para o relation_id
        internet_connector_async_send(sp, proto_value, da, dp, data);
    }
}

void on_internet_data(uint16_t source_id, uint8_t proto, std::shared_ptr<std::string> data) {
    uint32_t relation_id;
    if (relation_map.get(source_id, relation_id)) {
        std::string protocol = (proto == 6) ? "tcp" : "udp";
        filter_any_server_add_data(relation_id, *data, protocol, "", 0);
    }
    else {
        // lidar com o caso em que o source_id não está mapeado
    }
}

void core_run() {
    filter_any_server_async_recv(on_local_data);
    internet_connector_async_receive(on_internet_data);
}

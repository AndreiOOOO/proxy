#include "core.h"
#include "filter_settings.h"
#include "relation_map.h"

#define TEST_USING_INTERNET_CONNECTOR 1

static relation_map_t relation_map;
static filter_settings _filter_settings;

void init_gateway(uint32_t entry_id) {
    auto found =_filter_settings.get_forward_entry(entry_id);
    if (!found)
        return;
    if (found->initialized)
        return;

    found->initialized = true;
    gateway_new_gateway(entry_id);
    gateway_set_remote_endpoint(
        entry_id,
        found->address,
        found->port
    );
}

void on_local_data(
    uint32_t relation_source_id, 
    std::shared_ptr<std::string> data, 
    std::string protocol
) {
    uint32_t sa, da;
    uint16_t sp, dp;
    // get original endpoint relations
    bool found = filter_any_get_original_relation(relation_source_id, protocol, sa, sp, da, dp);
    if (!found)
        return;

    uint8_t proto_value = (protocol == "tcp") ? 6 : 17; // 6 para TCP, 17 para UDP

    auto current_relation = relation_map.get(relation_source_id);

    
    if (!current_relation) {
        auto entry = _filter_settings.get_foward_entry(
            current_relation->process_name,
            proto_value, sa, sp, da, dp
        );

        if (!entry)
            return;

        std::string process_name = "";
        filter_get_process_name_from_packet(sa, sp, da, dp, process_name);
        relation_map.add(relation_source_id, sp, proto_value, process_name);
        current_relation = relation_map.get(relation_source_id);
        current_relation->foward_id = entry->id;

        if (!entry->initialized) {
            init_gateway(entry->id);
        }
    }
      
    uint32_t gateway_id = current_relation->foward_id;

#if TEST_USING_INTERNET_CONNECTOR
    internet_connector_async_send(sp, proto_value, da, dp, data);
#else
    fowarder_send_packet(
        gateway_id,
        relation_source_id,
        proto_value, 
        da, dp, 
        data
    );

#endif
}

void on_internet_data(
    uint32_t relation_remaped_id, 
    uint32_t sa, uint16_t sp, 
    std::shared_ptr<std::string> data
) {
    auto _relation = relation_map.get_by_remaped_id(relation_remaped_id);
    if (_relation) {
        std::string protocol = (_relation->proto == 6) ? "tcp" : "udp";

        filter_any_server_add_data(_relation->source_id, *data, protocol, "", 0);
    }
    else {
        // lidar com o caso em que o source_id não está mapeado
    }
}

void core_run() {

    filter_any_server_async_recv(on_local_data);
#if TEST_USING_INTERNET_CONNECTOR

    auto _cb = [](uint32_t id, std::shared_ptr<std::string> data) {
        on_internet_data(id, -1, -1, data);
    };

    internet_connector_async_receive(_cb);

#else
    fowarder_set_recv_handler(on_internet_data);
#endif
}

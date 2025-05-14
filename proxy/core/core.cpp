#include "core.h"
#include "filter_settings.h"
#include "relation_map.h"

#define TEST_USING_INTERNET_CONNECTOR 1

// Variáveis estáticas
static relation_map_t relation_map;
static filter_settings _filter_settings;

// Funções
void init_gateway(uint32_t entry_id) {
    auto found = _filter_settings.get_forward_entry(entry_id);
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

    fowarder_set_gateway_recv(entry_id);
}


void on_local_data(
    uint32_t relation_source_id,
    std::shared_ptr<std::string> data,
    std::string protocol
) {
    std::cout << "\n " << __FILE__ << __FUNCTION__ << " data sz " << data->size();
    // Lógica para lidar com dados locais
    std::string process_name;
    uint32_t sa, da;
    uint16_t sp, dp;

    bool found = filter_any_get_original_relation(
        relation_source_id, protocol, process_name, sa, sp, da, dp
    );

    if (!found) {
        return;
    }
        

    uint8_t proto_value = (protocol == "tcp") ? 6 : 17;

    auto current_relation = relation_map.get(relation_source_id);
    if (!current_relation) {
        if (!process_name.size())
            return;

        auto entry = _filter_settings.get_foward_entry(
            process_name,
            proto_value, sa, sp, da, dp
        );

        if (!entry)
            return;

        relation_map.add(relation_source_id, sp, proto_value, process_name);
        current_relation = relation_map.get(relation_source_id);
        current_relation->foward_id = entry->id;

        if (!entry->initialized) {
            init_gateway(entry->id);
        }
    }

    uint32_t gateway_id = current_relation->foward_id;

    std::cout << "\n " << __FILE__ << __FUNCTION__ << " id " << gateway_id << " data sz " << data->size();

#if TEST_USING_INTERNET_CONNECTOR
    internet_connector_async_send(relation_source_id, proto_value, da, dp, data);
#else
    std::cout << "\n @@@@@@@@@@@@  " << relation_source_id;
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
    uint32_t gateway_id,
    uint32_t relation_source_id,
    uint32_t sa, uint16_t sp,
    std::shared_ptr<std::string> data
) {
    // Lógica para lidar com dados da internet
    std::cout << "\n " << __FILE__ << __FUNCTION__ << " id " << relation_source_id << " data sz " << data->size();
    auto _relation = relation_map.get(relation_source_id);
    if (_relation) {
        std::string protocol = (_relation->proto == 6) ? "tcp" : "udp";

        filter_any_server_add_data(_relation->source_id, *data, protocol, "", 0);
    }
    else {
        std::cout << "\n " << __FILE__ << __FUNCTION__ << " id " << relation_source_id << " data sz " << data->size();
        // Lidar com o caso em que o source_id não está mapeado
    }
}

void run_local_remote() {
    extern int core_remote_init();
#if TEST_USING_INTERNET_CONNECTOR == 0
    std::thread(core_remote_init).detach();
#endif
}

void core_run(boost::asio::io_context* io_context_) {
    filter_any_server_async_recv(on_local_data);

#if TEST_USING_INTERNET_CONNECTOR
    extern void init_internet_connector_on_main();
    init_internet_connector_on_main();
    auto _cb = [](uint32_t id_con, std::shared_ptr<std::string> data) {
        on_internet_data(-1, id_con, -1, -1, data);
        };

    internet_connector_async_receive(_cb);
#else
    fowarder_init(io_context_);
    run_local_remote();
    fowarder_set_recv_handler(on_internet_data);
#endif
}
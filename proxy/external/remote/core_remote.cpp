#include <iostream>
#include <string>
#include <memory>
#include <functional>
#include <boost/asio.hpp>
#include <map>

extern void fowarder_remote_init(boost::asio::io_context* io_context, unsigned short port);
extern void fowarder_remote_send_packet(uint32_t gateway_id, uint32_t connection_id, uint8_t protocol, uint32_t remote_address, uint16_t remote_port, std::shared_ptr<std::string> data);
extern void fowarder_remote_set_receive(std::function<void(uint32_t, uint32_t, uint8_t, uint32_t, uint16_t, std::shared_ptr<std::string>)> handler);

extern void internet_connector_init(boost::asio::io_context& io_context);
extern void internet_connector_async_send(uint32_t id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data);
extern void internet_connector_async_receive(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler);

class session_info {
public:
    session_info(uint32_t gateway_id) : gateway_id_(gateway_id) {}

    uint32_t get_internet_connector_id(uint32_t connection_id) {
        auto it = connection_map_.find(connection_id);
        if (it != connection_map_.end()) {
            return it->second;
        }
        else {
            uint32_t id = next_id_++;
            connection_map_[connection_id] = id;
            return id;
        }
    }

    uint32_t get_connection_id(uint32_t id) {
        for (auto& pair : connection_map_) {
            if (pair.second == id) {
                return pair.first;
            }
        }
        // não deve chegar aqui, pois o id deve ser válido
        return 0;
    }

private:
    uint32_t gateway_id_;
    uint32_t next_id_ = 1;
    std::map<uint32_t, uint32_t> connection_map_; // connection_id -> internet_connector_id
};

class core {
public:
    core(boost::asio::io_context& io_context) : io_context_(io_context) {}

    void init() {
        unsigned short port = 5000;
        fowarder_remote_init(&io_context_, port);
        internet_connector_init(io_context_);

        auto fowarder_remote_receive_handler = [this](uint32_t gateway_id, uint32_t connection_id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data) {
            session_info* session = get_session(gateway_id);
            uint32_t id = session->get_internet_connector_id(connection_id);
            internet_connector_async_send(id, proto, dest_address, dest_port, data);
            };

        auto internet_connector_receive_handler = [this](uint32_t id, std::shared_ptr<std::string> data) {
            for (auto& pair : session_map_) {
                session_info* session = pair.second.get();
                uint32_t connection_id = session->get_connection_id(id);
                if (connection_id != 0) {
                    fowarder_remote_send_packet(pair.first, connection_id, 0, 0, 0, data);
                    return;
                }
            }
            };

        fowarder_remote_set_receive(fowarder_remote_receive_handler);
        internet_connector_async_receive(internet_connector_receive_handler);
    }

    session_info* get_session(uint32_t gateway_id) {
        auto it = session_map_.find(gateway_id);
        if (it != session_map_.end()) {
            return it->second.get();
        }
        else {
            session_map_[gateway_id] = std::make_unique<session_info>(gateway_id);
            return session_map_[gateway_id].get();
        }
    }

private:
    boost::asio::io_context& io_context_;
    std::map<uint32_t, std::unique_ptr<session_info>> session_map_;
};

int core_init() {
    boost::asio::io_context io_context;
    core core(io_context);
    core.init();
    io_context.run();
    return 0;
}
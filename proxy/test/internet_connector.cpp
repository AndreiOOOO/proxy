#include <boost/asio.hpp>
#include <memory>
#include <queue>
#include <functional>
#include <map>
#include <iostream>
#include <chrono>

class internet_connector {
private:
    struct connection_data {
        uint32_t source_id;
        uint8_t proto;
        uint32_t dest_address;
        uint16_t dest_port;
        std::shared_ptr<std::string> data;
    };

    struct connection {
        std::shared_ptr<boost::asio::ip::tcp::socket> socket;
        boost::asio::ip::tcp::endpoint endpoint;
        std::queue<std::shared_ptr<connection_data>> send_queue;
        std::array<uint8_t, (uint16_t)-1> receive_buffer;
        bool sending = false;
        bool receiving = false;
        bool connecting = false;
        bool connected = false;
        bool socket_closing = false;
        std::chrono::steady_clock::time_point socket_close_timeout;
    };

    internet_connector(boost::asio::io_context& io_context)
        : io_context_(io_context) {}

    ~internet_connector() {}

public:
    static internet_connector& get_instance(boost::asio::io_context& io_context) {
        static internet_connector instance(io_context);
        return instance;
    }

    void async_send(uint32_t source_id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data) {
        auto connection_data_ptr = create_connection_data(source_id, proto, dest_address, dest_port, data);
        auto connection_ptr = get_or_create_connection(source_id, dest_address, dest_port);
        if (connection_ptr->socket_closing) {
            schedule_packet(connection_data_ptr);
            return;
        }
        connection_ptr->send_queue.push(connection_data_ptr);
        do_send(source_id);
    }

    void async_receive(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler) {
        receive_handler_ = handler;
        for (auto& connection : connections_) {
            do_receive(connection.first);
        }
    }

private:
    std::shared_ptr<connection_data> create_connection_data(uint32_t source_id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data) {
        auto connection_data_ptr = std::make_shared<connection_data>();
        connection_data_ptr->source_id = source_id;
        connection_data_ptr->proto = proto;
        connection_data_ptr->dest_address = dest_address;
        connection_data_ptr->dest_port = dest_port;
        connection_data_ptr->data = data;
        return connection_data_ptr;
    }

    std::shared_ptr<connection> get_or_create_connection(uint32_t source_id, uint32_t dest_address, uint16_t dest_port) {
        auto it = connections_.find(source_id);
        if (it == connections_.end()) {
            connections_[source_id] = std::make_shared<connection>();
            connections_[source_id]->endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4(dest_address), dest_port);
            establish_connection(source_id);
        }
        return connections_[source_id];
    }

    std::shared_ptr<connection> get_connection(uint32_t source_id) {
        auto it = connections_.find(source_id);
        if (it != connections_.end()) {
            return it->second;
        }
        return nullptr;
    }

    void schedule_packet(std::shared_ptr<connection_data> connection_data_ptr) {
        io_context_.post([this, connection_data_ptr]() {
            receive_handler_(connection_data_ptr->source_id, std::make_shared<std::string>());
            });
    }

    void establish_connection(uint32_t source_id) {
        auto connection_ptr = get_connection(source_id);
        if (connection_ptr->connecting || connection_ptr->connected) {
            return;
        }

        if (!connection_ptr->socket) {
            connection_ptr->socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
        }

        connection_ptr->connecting = true;
        connection_ptr->socket->async_connect(connection_ptr->endpoint, [this, source_id](const boost::system::error_code& error) {
            auto connection_ptr = get_connection(source_id);
            connection_ptr->connecting = false;
            if (!error) {
                connection_ptr->connected = true;
                do_send(source_id);
                do_receive(source_id);
            }
            else {
                handle_socket_error(source_id);
            }
            });
    }

    void do_send(uint32_t source_id) {
        auto connection_ptr = get_connection(source_id);
        if (!connection_ptr || !connection_ptr->socket || !connection_ptr->connected) {
            if (connection_ptr && !connection_ptr->connecting && !connection_ptr->connected) {
                establish_connection(source_id);
            }
            return;
        }

        if (connection_ptr->connecting) {
            return;
        }
        if (connection_ptr->sending) {
            return;
        }
        if (connection_ptr->send_queue.empty()) {
            return;
        }

        connection_ptr->sending = true;
        auto connection_data_ptr = connection_ptr->send_queue.front();
        connection_ptr->send_queue.pop();

        boost::asio::async_write(*connection_ptr->socket, boost::asio::buffer(*connection_data_ptr->data), [this, source_id, connection_ptr](const boost::system::error_code& error, size_t bytes_transferred) {
            connection_ptr->sending = false;
            if (!error) {
                do_send(source_id);
            }
            else {
                handle_socket_error(source_id);
            }
            });
    }

    void do_receive(uint32_t source_id) {
        auto connection_ptr = get_connection(source_id);
        if (!connection_ptr || !connection_ptr->socket || !connection_ptr->connected) {
            return;
        }

        if (connection_ptr->receiving) {
            return;
        }
        connection_ptr->receiving = true;

        connection_ptr->socket->async_read_some(boost::asio::buffer(connection_ptr->receive_buffer), [this, source_id, connection_ptr](const boost::system::error_code& error, size_t bytes_transferred) {
            connection_ptr->receiving = false;
            if (!error) {
                auto receive_buffer = std::make_shared<std::string>(reinterpret_cast<char*>(connection_ptr->receive_buffer.data()), bytes_transferred);
                receive_handler_(source_id, receive_buffer);
                do_receive(source_id);
            }
            else {
                handle_socket_error(source_id);
            }
            });
    }

    void handle_socket_error(uint32_t source_id) {
        auto connection_ptr = get_connection(source_id);
        if (connection_ptr->socket_closing) {
            return;
        }
        connection_ptr->socket_closing = true;
        connection_ptr->socket_close_timeout = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        close_socket(connection_ptr);
        schedule_socket_release(source_id);
        io_context_.post([this, source_id]() {
            receive_handler_(source_id, std::make_shared<std::string>());
            });
    }

    void close_socket(std::shared_ptr<connection> connection_ptr) {
        try {
            if (connection_ptr->socket) {
                connection_ptr->socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
                connection_ptr->socket->close();
            }
        }
        catch (const boost::system::system_error& e) {
            std::cerr << "Erro ao fechar o socket: " << e.what() << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "Erro ao fechar o socket: " << e.what() << std::endl;
        }
    }

    void schedule_socket_release(uint32_t source_id) {
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context_);
        timer->expires_after(std::chrono::seconds(30));
        timer->async_wait([this, source_id](const boost::system::error_code& error) {
            release_socket(source_id);
            });
    }

    void release_socket(uint32_t source_id) {
        auto it = connections_.find(source_id);
        if (it != connections_.end()) {
            connections_.erase(it);
        }
    }

    boost::asio::io_context& io_context_;
    std::map<uint32_t, std::shared_ptr<connection>> connections_;
    std::function<void(uint32_t, std::shared_ptr<std::string>)> receive_handler_;
};

internet_connector* internet_connector_instance = nullptr;

void internet_connector_init(boost::asio::io_context& io_context) {
    if (!internet_connector_instance) {
        internet_connector_instance = &internet_connector::get_instance(io_context);
    }
}

void internet_connector_async_send(uint32_t source_id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data) {
    if (internet_connector_instance) {
        internet_connector_instance->async_send(source_id, proto, dest_address, dest_port, data);
    }
}

void internet_connector_async_receive(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler) {
    if (internet_connector_instance) {
        internet_connector_instance->async_receive(handler);
    }
}
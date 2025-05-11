#include <boost/asio.hpp>
#include <memory>
#include <queue>
#include <functional>
#include <map>


class internet_connector {
private:
    struct connection_data {
        uint16_t source_id;
        uint8_t proto;
        uint32_t dest_address;
        uint16_t dest_port;
        std::shared_ptr<std::string> data;
    };

    internet_connector(boost::asio::io_context& io_context)
        : io_context_(io_context), socket_(std::make_shared<boost::asio::ip::tcp::socket>(io_context)) {}

    ~internet_connector() {}

public:
    static internet_connector& get_instance(boost::asio::io_context& io_context) {
        static internet_connector instance(io_context);
        return instance;
    }

    void async_send(uint16_t source_id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data) {
        auto connection_data_ptr = std::make_shared<connection_data>();
        connection_data_ptr->source_id = source_id;
        connection_data_ptr->proto = proto;
        connection_data_ptr->dest_address = dest_address;
        connection_data_ptr->dest_port = dest_port;
        connection_data_ptr->data = data;

        send_queue_[source_id].push(connection_data_ptr);

        do_send(source_id);
    }

    void async_receive(std::function<void(uint16_t, uint8_t, std::shared_ptr<std::string>)> handler) {
        receive_handler_ = handler;
        // Implementação da recepção de dados...
    }

private:
    void do_send(uint16_t source_id) {
        if (send_queue_[source_id].empty()) {
            return;
        }

        auto connection_data_ptr = send_queue_[source_id].front();
        send_queue_[source_id].pop();

        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address_v4(connection_data_ptr->dest_address), connection_data_ptr->dest_port);

        socket_->async_connect(endpoint, [this, connection_data_ptr](const boost::system::error_code& error) {
            if (!error) {
                boost::asio::async_write(*socket_, boost::asio::buffer(*connection_data_ptr->data), [this, connection_data_ptr](const boost::system::error_code& error, size_t bytes_transferred) {
                    if (!error) {
                        do_send(connection_data_ptr->source_id);
                    }
                    else {
                        // Tratar erro
                    }
                    });
            }
            else {
                // Tratar erro
            }
            });
    }

    boost::asio::io_context& io_context_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
    std::map<uint16_t, std::queue<std::shared_ptr<connection_data>>> send_queue_;
    std::function<void(uint16_t, uint8_t, std::shared_ptr<std::string>)> receive_handler_;
};

internet_connector* internet_connector_instance = nullptr;

void internet_connector_init(boost::asio::io_context& io_context) {
    if (!internet_connector_instance) {
        internet_connector_instance = &internet_connector::get_instance(io_context);
    }
}

void internet_connector_async_send(uint16_t source_id, uint8_t proto, uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data) {
    if (internet_connector_instance) {
        internet_connector_instance->async_send(source_id, proto, dest_address, dest_port, data);
    }
}

void internet_connector_async_receive(std::function<void(uint16_t, uint8_t, std::shared_ptr<std::string>)> handler) {
    if (internet_connector_instance) {
        internet_connector_instance->async_receive(handler);
    }
}

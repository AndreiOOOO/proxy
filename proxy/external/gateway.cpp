#include <boost/asio.hpp>
#include <string>
#include <queue>
#include <memory>
#include <functional>
#include <iostream>
#include <map>

class client_gateway {
public:
    client_gateway(boost::asio::io_context* io_context, uint32_t id)
        : io_context_(io_context), id_(id), connected_(false),
        connecting_(false), receiving_(false), sending_(false), socket_(*io_context_) {}

    void set_remote_endpoint(uint32_t ip, uint16_t port) {
        remote_endpoint_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4(ip), port);
    }

    void add_data(std::shared_ptr<std::string> data) {
        send_queue_.push(data);
        if (!connecting_ && !connected_) {
            connect();
        }
        else {
            send_next();
        }
    }

    void async_recv(std::function<void(std::shared_ptr<std::string>)> handler) {
        if (recv_handler_) {
            // Já existe um handler de recebimento, não é permitido ter mais de um
            return;
        }
        recv_handler_ = handler;
        if (connected_ && !receiving_) {
            start_read();
        }
    }

    void reset() {
        if (connected_) {
            socket_.close();
            connected_ = false;
        }
        sending_ = false;
        receiving_ = false;
        send_queue_ = std::queue<std::shared_ptr<std::string>>();
        if (on_restart_handler_) {
            on_restart_handler_(id_);
        }
    }

    void set_on_restart(std::function<void(uint32_t)> handler) {
        on_restart_handler_ = handler;
    }

private:
    void connect() {
        if (connected_ || connecting_) {
            return;
        }
        connecting_ = true;
        socket_.async_connect(remote_endpoint_,
            [this](const boost::system::error_code& error) {
                if (!error) {
                    connected_ = true;
                    connecting_ = false;
                    if (recv_handler_) {
                        start_read();
                    }
                    send_next();
                }
                else {
                    connecting_ = false;
                    reset();
                }
            });
    }

    void send_next() {
        if (sending_ || send_queue_.empty() || !connected_) {
            return;
        }
        sending_ = true;
        std::shared_ptr<std::string> data = send_queue_.front();
        send_queue_.pop();
        boost::asio::async_write(socket_, boost::asio::buffer(*data),
            [this](const boost::system::error_code& error, size_t bytes_transferred) {
                sending_ = false;
                if (error) {
                    reset();
                }
                else {
                    send_next();
                }
            });
    }

    void start_read() {
        if (receiving_ || !connected_) {
            return;
        }
        receiving_ = true;
        buffer.resize(1024);
        socket_.async_read_some(boost::asio::buffer(buffer),
            [this](const boost::system::error_code& error, size_t bytes_transferred) {
                receiving_ = false;
                if (!error) {
                    std::shared_ptr<std::string> data = std::make_shared<std::string>(buffer.data(), bytes_transferred);
                    if (recv_handler_) {
                        recv_handler_(data);
                    }
                    start_read();
                }
                else {
                    reset();
                }
            });
    }

    boost::asio::io_context* io_context_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::endpoint remote_endpoint_;
    bool connected_;
    bool connecting_;
    bool receiving_;
    bool sending_;
    uint32_t id_;
    std::queue<std::shared_ptr<std::string>> send_queue_;
    std::function<void(std::shared_ptr<std::string>)> recv_handler_;
    std::function<void(uint32_t)> on_restart_handler_;
    std::vector<char> buffer;
};

class gateway_manager {
public:
    gateway_manager(boost::asio::io_context* io_context) {
        io_context_ = io_context;
    }

    uint32_t new_gateway(uint32_t id) {
        if (gateways_.find(id) != gateways_.end()) {
            return id;
        }
        gateways_[id] = std::make_shared<client_gateway>(io_context_, id);
        return id;
    }

    void set_remote_endpoint(uint32_t id, uint32_t ip, uint16_t port) {
        if (gateways_.find(id) != gateways_.end()) {
            gateways_[id]->set_remote_endpoint(ip, port);
        }
    }

    void add_data(uint32_t id, std::shared_ptr<std::string> data) {
        if (gateways_.find(id) != gateways_.end()) {
            gateways_[id]->add_data(data);
        }
    }

    void async_recv(
        uint32_t id,
        std::function<void(uint32_t id, std::shared_ptr<std::string>)> handler
    ) {
        if (gateways_.find(id) != gateways_.end()) {
            gateways_[id]->async_recv(
                [handler, id](std::shared_ptr<std::string> data) {
                    handler(id, data);
                }
            );
        }
    }

    void reset_gateway(uint32_t id) {
        if (gateways_.find(id) != gateways_.end()) {
            gateways_[id]->reset();
        }
    }

    void set_on_restart(uint32_t id, std::function<void(uint32_t)> handler) {
        if (gateways_.find(id) != gateways_.end()) {
            gateways_[id]->set_on_restart(handler);
        }
    }

private:
    std::map<uint32_t, std::shared_ptr<client_gateway>> gateways_;
    boost::asio::io_context* io_context_;
};

gateway_manager* manager = nullptr;

void gateway_init(boost::asio::io_context* io_context) {
    if (!manager) {
        manager = new gateway_manager(io_context);
    }
}

uint32_t gateway_new_gateway(uint32_t id) {
    return manager->new_gateway(id);
}

void gateway_set_remote_endpoint(uint32_t id, uint32_t ip, uint16_t port) {
    manager->set_remote_endpoint(id, ip, port);
}

void gateway_add_data(uint32_t id, std::shared_ptr<std::string> data) {
    manager->add_data(id, data);
}

void gateway_async_recv(
    uint32_t gateway_id,
    std::function<void(uint32_t gateway_id, std::shared_ptr<std::string>)> handler
) {
    manager->async_recv(gateway_id, handler);
}

void gateway_reset(uint32_t id) {
    manager->reset_gateway(id);
}

void gateway_set_on_restart(uint32_t id, std::function<void(uint32_t)> handler) {
    manager->set_on_restart(id, handler);
}
#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <functional>
#include <map>
#include <queue>
#include <mutex>

class gateway_remote {
public:
    gateway_remote(boost::asio::io_context* io_context) : io_context_(io_context), acceptor_(nullptr) {}

    void init(unsigned short port, const std::string& address = "") {
        if (address.empty()) {
            acceptor_ = std::make_shared<boost::asio::ip::tcp::acceptor>(*io_context_, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));
        }
        else {
            boost::asio::ip::address addr = boost::asio::ip::make_address(address);
            acceptor_ = std::make_shared<boost::asio::ip::tcp::acceptor>(*io_context_, boost::asio::ip::tcp::endpoint(addr, port));
        }
        start_accept();
    }

    void start_accept() {
        std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::make_shared<boost::asio::ip::tcp::socket>(*io_context_);
        acceptor_->async_accept(*socket, [this, socket](const boost::system::error_code& error) {
            if (!error) {
                boost::asio::ip::tcp::endpoint endpoint = socket->remote_endpoint();
                sockets_[std::make_pair(endpoint.address().to_string(), endpoint.port())] = socket;
                start_recv(socket);
            }
            start_accept();
            });
    }

    void start_recv(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
        std::shared_ptr<std::vector<char>> recv_buffer = std::make_shared<std::vector<char>>(1024);
        socket->async_read_some(boost::asio::buffer(*recv_buffer), [this, socket, recv_buffer](const boost::system::error_code& error, size_t bytes_transferred) {
            if (error) {
                remove_socket(socket);
                return;
            }
            boost::asio::ip::tcp::endpoint endpoint = socket->remote_endpoint();
            receive_handler_(endpoint.address().to_string(), endpoint.port(), std::make_shared<std::string>(recv_buffer->begin(), recv_buffer->begin() + bytes_transferred));
            start_recv(socket);
            });
    }

    void send_data(const std::string& ip, unsigned short port, std::shared_ptr<std::string> data) {
        auto it = sockets_.find(std::make_pair(ip, port));
        if (it != sockets_.end()) {
            if (sending_[it->second.get()]) {
                send_queue_[it->second.get()].push(data);
                return;
            }
            sending_[it->second.get()] = true;
            boost::asio::async_write(*it->second, boost::asio::buffer(*data), [this, it](const boost::system::error_code& error, size_t bytes_transferred) {
                handle_send(it->second, error);
                });
        }
    }

    void send_data_from_queue(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
        if (!send_queue_[socket.get()].empty()) {
            std::shared_ptr<std::string> next_data = send_queue_[socket.get()].front();
            send_queue_[socket.get()].pop();
            boost::asio::async_write(*socket, boost::asio::buffer(*next_data), [this, socket](const boost::system::error_code& error, size_t bytes_transferred) {
                handle_send(socket, error);
                });
        }
        else {
            sending_[socket.get()] = false;
        }
    }

    void handle_send(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::system::error_code& error) {
        if (error) {
            remove_socket(socket);
            return;
        }
        if (!send_queue_[socket.get()].empty()) {
            send_data_from_queue(socket);
        }
        else {
            sending_[socket.get()] = false;
        }
    }

    void remove_socket(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
        try {
            socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            socket->close();
        }
        catch (const boost::system::system_error& e) {
            std::cerr << "Erro ao fechar socket: " << e.what() << std::endl;
        }
        boost::asio::ip::tcp::endpoint endpoint = socket->remote_endpoint();
        sockets_.erase(std::make_pair(endpoint.address().to_string(), endpoint.port()));
        if (on_close_handler_) {
            on_close_handler_(endpoint.address().to_string(), endpoint.port());
        }
    }

    void set_receive_handler(std::function<void(const std::string&, unsigned short, std::shared_ptr<std::string>)> handler) {
        receive_handler_ = handler;
    }

    void set_on_close_handler(std::function<void(const std::string&, unsigned short)> handler) {
        on_close_handler_ = handler;
    }

private:
    boost::asio::io_context* io_context_;
    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    std::map<std::pair<std::string, unsigned short>, std::shared_ptr<boost::asio::ip::tcp::socket>> sockets_;
    std::map<boost::asio::ip::tcp::socket*, std::queue<std::shared_ptr<std::string>>> send_queue_;
    std::map<boost::asio::ip::tcp::socket*, bool> sending_;
    std::function<void(const std::string&, unsigned short, std::shared_ptr<std::string>)> receive_handler_;
    std::function<void(const std::string&, unsigned short)> on_close_handler_;
};

gateway_remote* gateway;

void gateway_remote_init(boost::asio::io_context* io_context, unsigned short port, const std::string& address = "") {
    gateway = new gateway_remote(io_context);
    gateway->init(port, address);
}

void gateway_set_receive_callback(std::function<void(const std::string&, unsigned short, std::shared_ptr<std::string>)> handler) {
    gateway->set_receive_handler(handler);
}

void gateway_add_data(const std::string& ip, unsigned short port, std::shared_ptr<std::string> data) {
    std::cout << "\n " << __FILE__ << __FUNCTION__ << " data sz " << data->size();
    gateway->send_data(ip, port, data);
}

void gateway_set_on_close(std::function<void(const std::string&, unsigned short)> handler) {
    gateway->set_on_close_handler(handler);
}
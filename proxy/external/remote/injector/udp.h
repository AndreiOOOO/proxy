
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <map>
#include <memory>
#include <queue>

class UDPInjector {
public:
    UDPInjector(boost::asio::io_service& io_service) : io_service_(io_service) {}

    void send(int id, uint32_t destAddress, uint16_t destPort,
        std::shared_ptr<std::string> data);

    void async_recv(std::function<void(int, std::shared_ptr<std::string>)> handler);

private:
    void handleSend(int id, const boost::system::error_code& error,
        size_t bytes_transferred);

    void startRecv(int id);

    void handleRecv(int id, const boost::system::error_code& error, size_t bytes_transferred);

    boost::asio::io_service& io_service_;
    std::map<int, std::shared_ptr<boost::asio::ip::udp::socket>> sockets_;
    std::map<int, boost::asio::ip::udp::endpoint> remoteEndpoints_;
    std::map<int, std::array<char, 1024>> recvBuffers_;
    std::function<void(int, std::shared_ptr<std::string>)> handler_;
};
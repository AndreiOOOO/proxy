
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <map>
#include <memory>
#include <queue>


class TCPInjector {
public:
    TCPInjector(boost::asio::io_service& io_service) : io_service_(io_service) {}

    void send(int id, uint32_t destAddress, uint16_t destPort,
        std::shared_ptr<std::string> data);

    void async_recv(std::function<void(int, std::shared_ptr<std::string>)> handler);

private:
    struct SocketState {
        SocketState() {
            recvBuffer = std::make_shared<std::string>();
            recvBuffer->resize((uint16_t)-1);
        }
        std::shared_ptr<boost::asio::ip::tcp::socket> socket;
        bool connected = false;
        std::queue<std::shared_ptr<std::string>> sendQueue;
        std::shared_ptr<std::string> recvBuffer;
        bool receiving = false;
    };

    void handleConnect(int id, const boost::system::error_code& error);

    void sendNextPacket(int id);

    void handleWrite(int id, const boost::system::error_code& error, size_t bytes_transferred);

    void startRecv(int id);

    void handleRecv(int id, const boost::system::error_code& error, size_t bytes_transferred);

    boost::asio::io_service& io_service_;
    std::map<int, std::shared_ptr<SocketState>> sockets_;
    std::function<void(int, std::shared_ptr<std::string>)> handler_;
};
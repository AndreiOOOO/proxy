#include <string>
#include <vector>

struct gateway_info {
	std::string name;
	std::string addresss;
	uint16_t port;
};

class settings {
	std::vector < std::string > get_processes() {
		return { "tibia.exe", "tbiia2.exe" };
	}

	std::vector < gateway_info > get_gateways() {
		std::vector < gateway_info > retval;
		gateway_info _one;

		_one.name = "localtest";
		_one.addresss = "127.0.0.1";
		_one.port = 1000;

		retval.push_back(_one);

		return retval;
	}
};
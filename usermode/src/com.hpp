#pragma once
#include "defs.hpp"
//#include <iostream>
//#include <vector>
//#include <map>
#include <chrono>
#include <functional>
using namespace std::placeholders;

//#include <windows.h>
//#include <urlmon.h>
//#include <sstream>
//#include <iomanip>

//#define WIN32_LEAN_AND_MEAN

#define ASIO_STANDALONE 1
#define _WEBSOCKETPP_CPP11_TYPE_TRAITS_
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/client.hpp>
using websocketpp::client;
using websocketpp::connection_hdl;

#include "mem.hpp"



//#include <curl/curl.h>
//#include <json/json.hpp>
//using JSON = nlohmann::json;

//#pragma comment(lib, "libcurl.lib")
//#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "Normaliz.lib")
//#pragma comment(lib, "Crypt32.lib")
//#pragma comment(lib, "Wldap32.lib")
//#pragma comment(lib, "WinINet.lib")
//#pragma comment(lib, "urlmon.lib")
//#pragma comment(lib, "libcurl.lib")
//#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "Normaliz.lib")
//#pragma comment(lib, "Crypt32.lib")
//#pragma comment(lib, "Wldap32.lib")


class _WSClient {
public:
	client<websocketpp::config::asio>::connection_ptr con;
	//std::mutex mtx;

	_WSClient() { //: aTimer(ioService) {
		c.init_asio();
		c.set_open_handler(bind(&_WSClient::on_open, this, ::_1));
		c.set_close_handler(bind(&_WSClient::on_close, this, ::_1));
		c.set_message_handler(bind(&_WSClient::on_message, this, ::_1, ::_2));
	}

	int setup(const std::string& url, const char* authKey) {
		user = authKey;
		websocketpp::lib::error_code error;
		con = c.get_connection(url, error);

		if (error) {
			printf("con error: %s\n", error.message().c_str());
			return error.value();
		}

		c.connect(con);
		//c.run();
		std::thread([this]() { c.run(); }).detach();
		return error.value();
	}

	bool isClosed() {
		//std::lock_guard<std::mutex> lock(mtx);
		return !this->con || this->con->get_state() == websocketpp::session::state::closed;
	}

	void sendPacket(const std::shared_ptr<Packet>& packet) {
		if (isClosed()) return;

		JSON j = packet->serialize();
		j["op"] = j["id"];
		j.erase("id");
		j["type"] = 1;
		std::string jsonString = j.dump();

		std::thread([this, jsonString]() {
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			this->c.send(this->con->get_handle(), jsonString, websocketpp::frame::opcode::text);
		}).detach();

		//this->c.send(con->get_handle(), jsonString, websocketpp::frame::opcode::text);
		/*aTimer.expires_from_now(std::chrono::milliseconds(100));
		aTimer.async_wait([this, j](const std::error_code& ec) {
			if (!ec) {
				this->c.send(con->get_handle(), j, websocketpp::frame::opcode::text);
			}
			});*/
	}

	std::vector<char> GetMapper() {
		return {};
	}

	std::vector<char> GetDriver() {
		return {};
	}

private:
	//std::mutex mtx;
	client<websocketpp::config::asio> c;
	//websocketpp::lib::asio::steady_timer aTimer;
	//websocketpp::lib::asio::io_service ioService;
	std::string user;
	std::vector<Proc> procList;

	void on_open(connection_hdl hdl) {
		printf("ws connected\n");

		/*std::vector<Proc> procList = {
			// REMOVED DATA
		};*/

		//std::vector<Proc> procList = proc::getProcesses();

		//PacketData packetData;
		// REMOVED DATA
		//packetData.processes = procList;		

		//InitPacketC2S initPacket(0, packetData);
		//std::shared_ptr<Packet> initPacket = Packet::packetRegistry[0](packetData);
		//sendPacket(initPacket);

		this->procList = proc::getProcesses();
		// we have to sleep here because websocketpp will group these messages together otherwise idk y im prob retarded
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
		//packetData.processes = procList;
		//std::shared_ptr<Packet> kaPacket = Packet::packetRegistry[1](packetData);
		

		// REMOVED DATA
		//startPL();
		//sendKeepAlive();
		//startKA();
	}

	void on_close(connection_hdl hdl) {
		printf("ws disconnected\n");
		con = nullptr;
		exit(1);
	}

	void on_message(connection_hdl hdl, client<websocketpp::config::asio>::message_ptr msg) {
		std::string data = msg->get_payload();
		printf("websocket message recv: %s\n", data.c_str());
		JSON j = JSON::parse(data);
		std::shared_ptr<Packet> packet = Packet::deserialize(j);

		if (!packet) {
			printf("unknown packet\n");
			return;
		}

		printf("id: %d | d: \n", packet->id);
		
		switch (packet->id) {
		case 3:
			ULONG procId = NULL, threadId = NULL;
			procId = 0;// REMOVED DATA

			//proc::GetProcIdThread("Valve001", &procId, &threadId);
			threadId = proc::GetWindowThread(procId);
			if (!procId || !threadId) {
				printf("invalid thread id or proc id\n");
				return;
			}

			driver.processId = procId;
			driver.threadId = threadId;
			printf("found proc and thread id: %p, %p\n", procId, threadId);
			if (!driver.processId || !driver.threadId) return;
			// REMOVED DATA hint: map from resp ;3
		}
	}

	void startPL() {
		std::thread([this]() {
			while (true) {
				if (this->isClosed()) break;
				this->procList = proc::getProcesses();
				std::this_thread::sleep_for(std::chrono::seconds(1));
			}
		}).detach();
	}

	void startKA() {
		std::thread([this]() {
			while (true) {
				if (this->isClosed()) break;
				std::this_thread::sleep_for(std::chrono::seconds(5));
				sendKeepAlive();
			}
		}).detach();
	}

	void sendKeepAlive() {
		//std::vector<Proc> procList = this->procList; //proc::getProcesses();

		//PacketData packetData;
		//// REMOVED DATA

		//std::shared_ptr<Packet> kaPacket = Packet::packetRegistry[1](packetData);
		//sendPacket(kaPacket);
	}
};


//curl_slist* AddHeaders(CURL* curl, const std::map<std::string, std::string>& headersMap) {
//	struct curl_slist* headers = NULL;
//
//	// add each element to list
//	for (const auto& pair : headersMap) {
//		std::string header = pair.first + ": " + pair.second;
//		headers = curl_slist_append(headers, header.c_str());
//	}
//
//	// set headers
//	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
//
//	// return pointer to headers so we can free it after use
//	return headers;
//}

//class _comm {
//private:
//	// from stackoverflow
//	static size_t StringCallback(char* contents, size_t size, size_t memSize, std::string* stream)
//	{
//		stream->append(contents, size * memSize);
//		return size * memSize;
//	}
//
//	static size_t FileCallback(void* contents, size_t size, size_t memSize, std::vector<char>* stream)
//	{
//		size_t totalSize = size * memSize;
//		stream->insert(stream->end(), (char*)contents, (char*)contents + totalSize);
//		return size * memSize;
//	}
//
//public:
//	// resp, and readbuf can be local vars but its here for debugging
//	std::string URL;
//	CURLcode resp;
//	std::map<std::string, std::string> headerMap;
//	std::string readBuf;
//
//	// setup communication
//	bool setup(const char* url, const char* authKey) {
//		if (this->init(url)) return 1;
//		std::string uAgent = "overkill-loader-stub_"; //std::string{ "User-Agent: overkill-loader-stub_" }.append// REMOVED DATA;
//		uAgent = uAgent.append(// REMOVED DATA);
//
//		headerMap.insert(std::pair<std::string, std::string>("User-Agent", uAgent));
//		headerMap.insert(std::pair<std::string, std::string>("Authorization", authKey));
//		return 0;
//	}
//
//	// init communication
//	bool init(const char* url) {
//		this->URL = url;
//		return 0;
//	}
//
//	// shellcode before downloading everything here
//	std::vector<char> hexToByteChars(const std::string& hex) {
//		std::vector<char> bytes;
//		for (size_t i = 0; i < hex.length(); i += 2) {
//			std::string byteString = hex.substr(i, 2);
//			char byte = (char)(strtol(byteString.c_str(), nullptr, 16));
//			bytes.push_back(byte);
//		}
//		return bytes;
//	}
//
//	// downloads the mapper from the authenticated endpoint
//	std::vector<char> GetBuild(std::string downType) {
//		if (this->URL.empty()) return {};
//		readBuf.clear();
//
//		// init request
//		CURL* curl = curl_easy_init();
//		if (!curl) return {};
//
//		std::string fullURL = // REMOVED DATA
//		// url
//		curl_easy_setopt(curl, CURLOPT_URL, fullURL.c_str());
//		// write function
//		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, this->StringCallback);
//		// to buffer
//		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuf);
//		// add headers
//		curl_slist* headers = AddHeaders(curl, headerMap);
//
//		// make the request
//		resp = curl_easy_perform(curl);
//
//		// cleanup
//		curl_slist_free_all(headers);
//		curl_easy_cleanup(curl);
//		
//		// error
//		if (resp != 0) {
//			printf("comm failed %s\n", fullURL.c_str());
//			return {};
//		}
//
//		JSON parsedResp = JSON::parse(readBuf);
//		std::vector<char> bytes = hexToByteChars(parsedResp["data"]);
//		
//		return bytes;
//	}
//
//	std::vector<char> GetMapper() {
//		return GetBuild("");
//	}
//
//	std::vector<char> GetDriver() {
//		return GetBuild("driver");
//	}
//};

//_comm comm;
#if _DROPPER
_comm comm;
#else
_WSClient comm;
#endif
#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>

#include <json/json.hpp>
using JSON = nlohmann::json;

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

struct Proc {
	int pid;

	Proc() {}
	Proc(int p) : pid(p) {}
	Proc(const JSON& j) {
		if (j.contains("pid")) pid = j["pid"];
		// REMOVED DATA
	}

	JSON serialize() const {
		return JSON{ {"pid", pid} };
	}
};



// ================================= communication ================================= //
struct PacketData {
	int procId;
	std::vector<Proc> processes;

	PacketData() {}
	PacketData(const JSON& j) {
		// REMOVED DATA
		if (j.contains("procId")) procId = j["procId"];
		/*if (j.contains("processes")) {
			for (const auto& procData : j["processes"]) {
				processes.push_back(Proc(procData));
			}
		}*/
	}

	JSON serialize() const {
		JSON j = JSON::object();
		// REMOVED DATA
		if (!procId) j["procId"] = procId;
		/*if (!processes.empty()) {
			j["processes"] = JSON::array();
			for (const auto& process : processes) {
				j["processes"].push_back(process.serialize());
			}
		}*/

		return j;
	}	
};

class Packet {
public:
	int id;
	PacketData data;

	Packet(int id, const PacketData& data) : id(id), data(data) {}
	virtual ~Packet() = default;
	virtual int getId() const = 0;
	virtual JSON serialize() const = 0;

	// the factor
	static std::shared_ptr<Packet> deserialize(const JSON& j);

	// regi
	static void registerPacket(int id, std::function<std::shared_ptr<Packet>(const PacketData&)> creator);

	// unordered saves memory
	static std::unordered_map<int, std::function<std::shared_ptr<Packet>(const PacketData&)>> packetRegistry;
private:
	
	
};

// trust me this took me way too long too research and figure out
std::unordered_map<int, std::function<std::shared_ptr<Packet>(const PacketData&)>> Packet::packetRegistry;

void Packet::registerPacket(int id, std::function<std::shared_ptr<Packet>(const PacketData&)> creator) {
	packetRegistry[id] = creator;
}

std::shared_ptr<Packet> Packet::deserialize(const JSON& j) {
	if (!j.contains("op")) return nullptr;

	int id = j["op"];
	PacketData data(j["d"]);

	auto it = packetRegistry.find(id);
	if (it != packetRegistry.end()) {
		return it->second(data);
	}
	return nullptr;
}





// PACKETS REMOVED
class ExamplePacketC2S : public Packet {
public:
	ExamplePacketC2S(int id, const PacketData& data) : Packet(id, data) {}

	int getId() const override {
		return Packet::id;
	}

	JSON serialize() const override {
		return JSON{ {"id", getId()}, {"d", data.serialize()}};
	}
};
// ================================================================================= //

void registerPackets() {
	Packet::registerPacket(0, [](const PacketData& data) {
		return std::make_shared<ExamplePacketC2S>(0, data);
	});
}
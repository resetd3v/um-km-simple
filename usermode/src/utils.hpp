#pragma once
#include <wincrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>

#include <random>
using namespace std;

namespace utils {
    std::string wstringToString(const std::wstring& wstr) {
        // calc size (short for calculate btw)
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
        // init string
        std::string str(size, 0);
        // call winapi to convert
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size, NULL, NULL);

        return str;
    }

    // from stackoverflow generates a random string - mainly used for security reasons like random windows names to prevent fingerprinting
    string genRandStr(size_t length) {
        static thread_local mt19937 generator(random_device{}());
        static thread_local string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        shuffle(characters.begin(), characters.end(), generator);
        return characters.substr(0, length);
    }

    /*std::vector<char> hexToByteChars(const std::string& hex) {
        std::vector<char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
        	std::string byteString = hex.substr(i, 2);
        	char byte = (char)(strtol(byteString.c_str(), nullptr, 16));
        	bytes.push_back(byte);
        }
        return bytes;
    }*/

    std::vector<BYTE> hexStringToBytes(const std::string& hexThing) {
        std::vector<BYTE> bytes;
        for (size_t i = 0; i < hexThing.length(); i += 2) {
            std::string byteString = hexThing.substr(i, 2);
            BYTE byte = static_cast<BYTE>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    std::string calculateChecksum(const std::string& filePath) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        BYTE hash[20]; // SHA1 gives a 20 byte hash
        DWORD hashLen = sizeof(hash);

        // open the file
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            printf("[checksum] failed to open file\n");
            return "";
        }

        // init crypto provider
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            printf("[checksum] failed to acquire crypto context\n");
            return "";
        }

        // init the hash
        if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            printf("[checksum] failed to create hash\n");
            return "";
        }

        // read the file and hash it
        char buffer[4096];
        while (file.read(buffer, sizeof(buffer))) {
            CryptHashData(hHash, (BYTE*)buffer, file.gcount(), 0);
        }
        file.close();

        // finalize the hash
        CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

        // convert hash to hex string
        std::ostringstream oss;
        for (DWORD i = 0; i < hashLen; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        // cleanup
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return oss.str();
    }
}
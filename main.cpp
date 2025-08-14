#include "password_checkup.h"
#include <iostream>
#include <vector>

int main() {
    // 1. 准备一些模拟的泄露密码
    std::vector<std::string> leakedPasswords = {
        "password123",
        "qwerty",
        "123456",
        "letmein",
        "secret"
    };

    // 2. 服务器生成布隆过滤器
    std::vector<bool> bloomFilter = generateLeakedPasswordsBloomFilter(leakedPasswords);
    std::cout << "服务器已初始化，布隆过滤器大小: " << bloomFilter.size() << std::endl;

    // 3. 创建客户端和服务器实例
    PasswordCheckup client;
    PasswordCheckup server;

    // 4. 测试几个密码
    std::vector<std::string> testPasswords = {
        "password123",  // 应该被检测到（在泄露列表中）
        "mypassword",   // 不应该被检测到
        "qwerty",       // 应该被检测到
        "secure123!"    // 不应该被检测到
    };

    for (const std::string& password : testPasswords) {
        std::cout << "\n检查密码: " << password << std::endl;

        // 客户端准备数据
        auto [clientHashXorR, clientHashes] = client.clientPrepare(password);

        // 服务器处理请求
        std::vector<bool> serverResponse = server.serverProcess(clientHashXorR, clientHashes, bloomFilter);

        // 客户端验证结果
        std::string passwordHash = client.sha256(password);
        std::vector<int> indices = client.hashFunctions(passwordHash);
        bool isLeaked = client.clientVerify(serverResponse, indices);

        if (isLeaked) {
            std::cout << "警告: 该密码已在数据泄露中被发现！" << std::endl;
        }
        else {
            std::cout << "安全: 该密码未在已知数据泄露中发现。" << std::endl;
        }
    }

    return 0;
}

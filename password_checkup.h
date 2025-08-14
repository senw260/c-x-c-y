#ifndef PASSWORD_CHECKUP_H
#define PASSWORD_CHECKUP_H

#include <string>
#include <vector>
#include <cstdint>
#include <random>

// 哈希函数数量
const int NUM_HASH_FUNCTIONS = 3;

// 布隆过滤器大小 (2^20)
const int BLOOM_FILTER_SIZE = 1048576;

class PasswordCheckup {
private:
    // 随机数生成器
    std::mt19937_64 rng;

    // 生成随机64位值
    uint64_t generateRandom();

    // 哈希函数 - 将输入映射到布隆过滤器的索引
    std::vector<int> hashFunctions(const std::string& input);

    // 计算密码的SHA-256哈希
    std::string sha256(const std::string& input);

public:
    PasswordCheckup();

    // 客户端：准备要发送到服务器的数据
    std::pair<uint64_t, std::vector<uint64_t>> clientPrepare(const std::string& password);

    // 服务器：处理客户端请求
    std::vector<bool> serverProcess(uint64_t clientHashXorR, const std::vector<uint64_t>& clientHashes,
        const std::vector<bool>& bloomFilter);

    // 客户端：验证服务器返回的结果
    bool clientVerify(const std::vector<bool>& serverResponse, const std::vector<int>& indices);
};

// 生成模拟的泄露密码布隆过滤器
std::vector<bool> generateLeakedPasswordsBloomFilter(const std::vector<std::string>& leakedPasswords);

#endif // PASSWORD_CHECKUP_H
#pragma once

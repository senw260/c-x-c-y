#include "password_checkup.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <chrono>

PasswordCheckup::PasswordCheckup() {
    // 使用当前时间作为随机数种子
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    rng.seed(seed);
}

uint64_t PasswordCheckup::generateRandom() {
    return rng();
}

std::string PasswordCheckup::sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::vector<int> PasswordCheckup::hashFunctions(const std::string& input) {
    std::vector<int> indices(NUM_HASH_FUNCTIONS);

    // 对输入进行哈希
    std::string hash = sha256(input);

    // 使用哈希的不同部分生成多个索引
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        // 从哈希字符串中提取不同的部分
        std::string sub = hash.substr(i * 8, 8);
        // 转换为64位整数
        uint64_t val;
        std::stringstream ss;
        ss << std::hex << sub;
        ss >> val;
        // 映射到布隆过滤器大小范围内
        indices[i] = val % BLOOM_FILTER_SIZE;
    }

    return indices;
}

std::pair<uint64_t, std::vector<uint64_t>> PasswordCheckup::clientPrepare(const std::string& password) {
    // 1. 计算密码的哈希 H(p)
    std::string passwordHash = sha256(password);

    // 2. 生成随机值 r
    uint64_t r = generateRandom();

    // 3. 计算 H(p) 的前8字节作为64位整数
    uint64_t hp;
    std::stringstream ss;
    ss << std::hex << passwordHash.substr(0, 16);  // 16个十六进制字符 = 8字节
    ss >> hp;

    // 4. 计算 H(p) XOR r
    uint64_t hpXorR = hp ^ r;

    // 5. 生成用于布隆过滤器查询的哈希值
    std::vector<uint64_t> clientHashes;
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        // 为每个哈希函数生成一个随机值
        uint64_t ri = generateRandom();
        // 计算 H(p) 特定部分的哈希
        std::string subHash = sha256(passwordHash + std::to_string(i));
        uint64_t hpi;
        std::stringstream ss2;
        ss2 << std::hex << subHash.substr(0, 16);
        ss2 >> hpi;
        // 存储 hpi XOR ri
        clientHashes.push_back(hpi ^ ri);
    }

    return { hpXorR, clientHashes };
}

std::vector<bool> PasswordCheckup::serverProcess(uint64_t clientHashXorR,
    const std::vector<uint64_t>& clientHashes,
    const std::vector<bool>& bloomFilter) {
    std::vector<bool> response;

    // 服务器为每个哈希函数生成随机值 si
    std::vector<uint64_t> serverRandoms(NUM_HASH_FUNCTIONS);
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        serverRandoms[i] = generateRandom();
    }

    // 计算 r' = clientHashXorR XOR s0 (s0是第一个随机值)
    uint64_t rPrime = clientHashXorR ^ serverRandoms[0];

    // 处理每个哈希函数
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        // 计算 H(p) XOR r' XOR si
        uint64_t hashIndex = (clientHashes[i] ^ rPrime) ^ serverRandoms[i];
        // 映射到布隆过滤器大小范围内
        int index = hashIndex % BLOOM_FILTER_SIZE;
        // 确保索引非负
        if (index < 0) index += BLOOM_FILTER_SIZE;
        // 从布隆过滤器获取结果
        response.push_back(bloomFilter[index]);
    }

    return response;
}

bool PasswordCheckup::clientVerify(const std::vector<bool>& serverResponse, const std::vector<int>& indices) {
    // 检查所有哈希函数对应的位置是否都为true
    for (bool present : serverResponse) {
        if (!present) {
            return false;  // 密码不在泄露列表中
        }
    }
    return true;  // 密码可能在泄露列表中（布隆过滤器有假阳性可能）
}

std::vector<bool> generateLeakedPasswordsBloomFilter(const std::vector<std::string>& leakedPasswords) {
    std::vector<bool> bloomFilter(BLOOM_FILTER_SIZE, false);
    PasswordCheckup checker;

    for (const std::string& password : leakedPasswords) {
        std::string hash = checker.sha256(password);
        std::vector<int> indices = checker.hashFunctions(hash);

        for (int index : indices) {
            bloomFilter[index] = true;
        }
    }

    return bloomFilter;
}

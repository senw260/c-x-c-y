#include "password_checkup.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <chrono>

PasswordCheckup::PasswordCheckup() {
    // ʹ�õ�ǰʱ����Ϊ���������
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

    // ��������й�ϣ
    std::string hash = sha256(input);

    // ʹ�ù�ϣ�Ĳ�ͬ�������ɶ������
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        // �ӹ�ϣ�ַ�������ȡ��ͬ�Ĳ���
        std::string sub = hash.substr(i * 8, 8);
        // ת��Ϊ64λ����
        uint64_t val;
        std::stringstream ss;
        ss << std::hex << sub;
        ss >> val;
        // ӳ�䵽��¡��������С��Χ��
        indices[i] = val % BLOOM_FILTER_SIZE;
    }

    return indices;
}

std::pair<uint64_t, std::vector<uint64_t>> PasswordCheckup::clientPrepare(const std::string& password) {
    // 1. ��������Ĺ�ϣ H(p)
    std::string passwordHash = sha256(password);

    // 2. �������ֵ r
    uint64_t r = generateRandom();

    // 3. ���� H(p) ��ǰ8�ֽ���Ϊ64λ����
    uint64_t hp;
    std::stringstream ss;
    ss << std::hex << passwordHash.substr(0, 16);  // 16��ʮ�������ַ� = 8�ֽ�
    ss >> hp;

    // 4. ���� H(p) XOR r
    uint64_t hpXorR = hp ^ r;

    // 5. �������ڲ�¡��������ѯ�Ĺ�ϣֵ
    std::vector<uint64_t> clientHashes;
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        // Ϊÿ����ϣ��������һ�����ֵ
        uint64_t ri = generateRandom();
        // ���� H(p) �ض����ֵĹ�ϣ
        std::string subHash = sha256(passwordHash + std::to_string(i));
        uint64_t hpi;
        std::stringstream ss2;
        ss2 << std::hex << subHash.substr(0, 16);
        ss2 >> hpi;
        // �洢 hpi XOR ri
        clientHashes.push_back(hpi ^ ri);
    }

    return { hpXorR, clientHashes };
}

std::vector<bool> PasswordCheckup::serverProcess(uint64_t clientHashXorR,
    const std::vector<uint64_t>& clientHashes,
    const std::vector<bool>& bloomFilter) {
    std::vector<bool> response;

    // ������Ϊÿ����ϣ�����������ֵ si
    std::vector<uint64_t> serverRandoms(NUM_HASH_FUNCTIONS);
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        serverRandoms[i] = generateRandom();
    }

    // ���� r' = clientHashXorR XOR s0 (s0�ǵ�һ�����ֵ)
    uint64_t rPrime = clientHashXorR ^ serverRandoms[0];

    // ����ÿ����ϣ����
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        // ���� H(p) XOR r' XOR si
        uint64_t hashIndex = (clientHashes[i] ^ rPrime) ^ serverRandoms[i];
        // ӳ�䵽��¡��������С��Χ��
        int index = hashIndex % BLOOM_FILTER_SIZE;
        // ȷ�������Ǹ�
        if (index < 0) index += BLOOM_FILTER_SIZE;
        // �Ӳ�¡��������ȡ���
        response.push_back(bloomFilter[index]);
    }

    return response;
}

bool PasswordCheckup::clientVerify(const std::vector<bool>& serverResponse, const std::vector<int>& indices) {
    // ������й�ϣ������Ӧ��λ���Ƿ�Ϊtrue
    for (bool present : serverResponse) {
        if (!present) {
            return false;  // ���벻��й¶�б���
        }
    }
    return true;  // ���������й¶�б��У���¡�������м����Կ��ܣ�
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

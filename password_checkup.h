#ifndef PASSWORD_CHECKUP_H
#define PASSWORD_CHECKUP_H

#include <string>
#include <vector>
#include <cstdint>
#include <random>

// ��ϣ��������
const int NUM_HASH_FUNCTIONS = 3;

// ��¡��������С (2^20)
const int BLOOM_FILTER_SIZE = 1048576;

class PasswordCheckup {
private:
    // �����������
    std::mt19937_64 rng;

    // �������64λֵ
    uint64_t generateRandom();

    // ��ϣ���� - ������ӳ�䵽��¡������������
    std::vector<int> hashFunctions(const std::string& input);

    // ���������SHA-256��ϣ
    std::string sha256(const std::string& input);

public:
    PasswordCheckup();

    // �ͻ��ˣ�׼��Ҫ���͵�������������
    std::pair<uint64_t, std::vector<uint64_t>> clientPrepare(const std::string& password);

    // ������������ͻ�������
    std::vector<bool> serverProcess(uint64_t clientHashXorR, const std::vector<uint64_t>& clientHashes,
        const std::vector<bool>& bloomFilter);

    // �ͻ��ˣ���֤���������صĽ��
    bool clientVerify(const std::vector<bool>& serverResponse, const std::vector<int>& indices);
};

// ����ģ���й¶���벼¡������
std::vector<bool> generateLeakedPasswordsBloomFilter(const std::vector<std::string>& leakedPasswords);

#endif // PASSWORD_CHECKUP_H
#pragma once

#include "sm3.h"
#include <iostream>
#include <iomanip>
#include <chrono>

// ��������: ����Ϣ��SM3��ϣֵӦΪ
// 1ab21d8355cfa17f8e61194831e81a8f79426190
void testEmptyMessage() {
    std::string hash = SM3::hash("");
    std::cout << "����Ϣ����: " << (hash == "1ab21d8355cfa17f8e61194831e81a8f79426190" ? "ͨ��" : "ʧ��") << std::endl;
    std::cout << "��ϣֵ: " << hash << std::endl;
}

// ��������: "abc"��SM3��ϣֵӦΪ
// 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
void testABC() {
    std::string hash = SM3::hash("abc");
    std::cout << "abc����: " << (hash == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" ? "ͨ��" : "ʧ��") << std::endl;
    std::cout << "��ϣֵ: " << hash << std::endl;
}

// ���ܲ���: �������Ϣ�Ĺ�ϣֵ, ����ʱ��
void performanceTest() {
    const size_t DATA_SIZE = 1024 * 1024 * 10;  // 10MB
    std::vector<uint8_t> data(DATA_SIZE, 0x55);  // ���0x55

    auto start = std::chrono::high_resolution_clock::now();

    SM3 sm3;
    sm3.update(data.data(), data.size());
    std::string hash = sm3.final();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "���ܲ���: " << std::endl;
    std::cout << "���ݴ�С: " << DATA_SIZE / (1024 * 1024) << "MB" << std::endl;
    std::cout << "��ʱ: " << elapsed.count() << "��" << std::endl;
    std::cout << "�ٶ�: " << (DATA_SIZE / (1024 * 1024)) / elapsed.count() << "MB/s" << std::endl;
    std::cout << "��ϣֵ: " << hash << std::endl;
}

int main() {
    testEmptyMessage();
    std::cout << std::endl;
    testABC();
    std::cout << std::endl;
    performanceTest();

    return 0;
}

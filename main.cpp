#include "sm3.h"
#include <iostream>
#include <iomanip>
#include <chrono>

// 测试向量: 空消息的SM3哈希值应为
// 1ab21d8355cfa17f8e61194831e81a8f79426190
void testEmptyMessage() {
    std::string hash = SM3::hash("");
    std::cout << "空消息测试: " << (hash == "1ab21d8355cfa17f8e61194831e81a8f79426190" ? "通过" : "失败") << std::endl;
    std::cout << "哈希值: " << hash << std::endl;
}

// 测试向量: "abc"的SM3哈希值应为
// 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
void testABC() {
    std::string hash = SM3::hash("abc");
    std::cout << "abc测试: " << (hash == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" ? "通过" : "失败") << std::endl;
    std::cout << "哈希值: " << hash << std::endl;
}

// 性能测试: 计算大消息的哈希值, 测量时间
void performanceTest() {
    const size_t DATA_SIZE = 1024 * 1024 * 10;  // 10MB
    std::vector<uint8_t> data(DATA_SIZE, 0x55);  // 填充0x55

    auto start = std::chrono::high_resolution_clock::now();

    SM3 sm3;
    sm3.update(data.data(), data.size());
    std::string hash = sm3.final();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "性能测试: " << std::endl;
    std::cout << "数据大小: " << DATA_SIZE / (1024 * 1024) << "MB" << std::endl;
    std::cout << "耗时: " << elapsed.count() << "秒" << std::endl;
    std::cout << "速度: " << (DATA_SIZE / (1024 * 1024)) / elapsed.count() << "MB/s" << std::endl;
    std::cout << "哈希值: " << hash << std::endl;
}

int main() {
    testEmptyMessage();
    std::cout << std::endl;
    testABC();
    std::cout << std::endl;
    performanceTest();

    return 0;
}

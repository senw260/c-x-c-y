#ifndef SM3_H
#define SM3_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

// SM3算法实现类
class SM3 {
private:
    // 初始哈希值IV
    static const uint32_t IV[8];
    // 常量T_j (0-15轮: 0x79cc4519, 16-63轮: 0x7a879d8a)
    static const uint32_t T[64];

    // 8个状态寄存器
    uint32_t state[8];
    // 消息总长度(bit)
    uint64_t totalBits;
    // 缓存区(最多64字节)
    uint8_t buffer[64];
    // 缓存区已使用字节数
    size_t bufferSize;

    // 辅助函数: 循环左移
    static uint32_t rotateLeft(uint32_t x, int n);

    // 置换函数P0
    static uint32_t P0(uint32_t x);

    // 置换函数P1
    static uint32_t P1(uint32_t x);

    // 布尔函数FF_j
    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j);

    // 布尔函数GG_j
    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j);

    // 压缩函数: 处理一个512bit消息块
    void compress(const uint8_t* block);

public:
    // 构造函数: 初始化状态
    SM3();

    // 更新消息: 处理输入数据
    void update(const uint8_t* data, size_t len);
    void update(const std::string& data);

    // 完成计算: 处理剩余数据并生成最终哈希值
    void final(uint8_t* hash);
    std::string final();

    // 便捷接口: 直接计算数据的哈希值
    static std::string hash(const std::string& data);
    static void hash(const uint8_t* data, size_t len, uint8_t* hash);
};

#endif // SM3_H
#pragma once

#ifndef SM4_H
#define SM4_H

#include <vector>
#include <cstdint>

class SM4 {
private:
    // S盒（国标定义）
    static const uint8_t Sbox[256];
    // 固定参数FK和CK
    static const uint32_t FK[4];
    static const uint32_t CK[32];
    // 轮密钥（32个）
    uint32_t rk[32];

    // 辅助函数：字节拆分与合并
    static uint8_t get_uint8(uint32_t x, int i);
    static uint32_t put_uint32(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3);

    // 非线性变换（密钥扩展用）
    static uint32_t tau(uint32_t x);
    // 线性变换L（加密用）
    static uint32_t L(uint32_t x);
    // 线性变换L'（密钥扩展用）
    static uint32_t L_prime(uint32_t x);
    // 轮函数
    static uint32_t F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk);

public:
    // 构造函数：传入128位密钥（16字节）
    SM4(const std::vector<uint8_t>& key);

    // 加密：输入16字节明文，输出16字节密文
    void encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext);

    // 解密：输入16字节密文，输出16字节明文
    void decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext);
};

#endif // SM4_H

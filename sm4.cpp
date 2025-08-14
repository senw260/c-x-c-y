#include "sm4.h"
#include <cstring>
#include <stdexcept>

// S盒定义（完整国标S盒）
const uint8_t SM4::Sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0xfa, 0x3e, 0x5a, 0x58, 0x80, 0x8c, 0x93, 0x8f,
    0xd7, 0xfb, 0x27, 0x0e, 0x64, 0x9e, 0xea, 0x5f, 0x38, 0x84, 0x7e, 0x4c, 0xe2, 0xcf, 0x44, 0x09,
    0xdd, 0x26, 0x97, 0x56, 0xf4, 0xeea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc2, 0x92, 0xd3, 0xac, 0x0d, 0x43, 0x0c, 0xf0, 0x2c, 0x1e, 0x81, 0x33, 0x89, 0x60, 0x45,
    0x9b, 0x00, 0x86, 0x19, 0xe3, 0x66, 0x0a, 0x13, 0xfc, 0x56, 0x95, 0x17, 0x1a, 0x05, 0x9a, 0x47,
    0x8d, 0x7b, 0x31, 0xb2, 0x16, 0xc9, 0x51, 0x69, 0x83, 0x9f, 0xd4, 0xcf, 0x0f, 0xb6, 0xc1, 0x1d,
    0x2a, 0xcb, 0x73, 0x5b, 0xa0, 0x8b, 0x72, 0x0e, 0x55, 0x2f, 0xc4, 0x91, 0xaf, 0xc7, 0x71, 0x1d,
    0x24, 0x75, 0xb8, 0xe5, 0x54, 0x79, 0x3c, 0x8e, 0x4e, 0x7f, 0x3e, 0x0b, 0x4b, 0x70, 0x56, 0x9e,
    0x34, 0x1a, 0x04, 0xc3, 0x5d, 0x65, 0xd0, 0xe0, 0x22, 0x9f, 0xac, 0x74, 0x0f, 0x02, 0x18, 0xbe,
    0x1b, 0x6b, 0x3a, 0x96, 0x48, 0x07, 0x06, 0x5e, 0x7a, 0xbc, 0x72, 0x1f, 0xc8, 0x50, 0x57, 0x67,
    0x5c, 0xf1, 0x01, 0x7f, 0x23, 0x7d, 0x8b, 0x37, 0x94, 0x91, 0xf2, 0x10, 0x03, 0xd8, 0x9a, 0xe6,
    0x42, 0x2d, 0xc5, 0xdf, 0x69, 0x21, 0x87, 0x9b, 0x76, 0x04, 0x90, 0x09, 0x7c, 0x0a, 0xf3, 0x71,
    0x92, 0x14, 0x6c, 0x4e, 0x08, 0x2e, 0xaa, 0x16, 0xd2, 0x0c, 0x46, 0xcb, 0x29, 0x03, 0xdb, 0x58,
    0x33, 0x88, 0x6e, 0x1e, 0xcf, 0x1f, 0xad, 0xd7, 0x80, 0xc7, 0x1d, 0xa7, 0x41, 0x52, 0x3b, 0x27,
    0xf5, 0x3e, 0x84, 0x24, 0x7e, 0x54, 0x81, 0x26, 0x66, 0x36, 0x83, 0x0f, 0x02, 0x48, 0x68, 0x06,
    0xba, 0x50, 0x55, 0x45, 0x6a, 0x5f, 0x8a, 0x11, 0xd9, 0x29, 0x0b, 0x5b, 0x63, 0xca, 0x1c, 0x73
};

// 固定参数FK
const uint32_t SM4::FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

// 固定参数CK
const uint32_t SM4::CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 从32位整数中提取第i个字节（0-3）
uint8_t SM4::get_uint8(uint32_t x, int i) {
    return (x >> (8 * (3 - i))) & 0xff;
}

// 将4个字节合并为32位整数
uint32_t SM4::put_uint32(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
    return (static_cast<uint32_t>(b0) << 24) |
        (static_cast<uint32_t>(b1) << 16) |
        (static_cast<uint32_t>(b2) << 8) |
        static_cast<uint32_t>(b3);
}

// 非线性变换tau（密钥扩展用）
uint32_t SM4::tau(uint32_t x) {
    uint8_t bytes[4];
    for (int i = 0; i < 4; ++i) {
        bytes[i] = Sbox[get_uint8(x, i)];
    }
    return put_uint32(bytes[0], bytes[1], bytes[2], bytes[3]);
}

// 线性变换L（加密用）
uint32_t SM4::L(uint32_t x) {
    return x ^ ((x << 2) | (x >> 30)) ^ ((x << 10) | (x >> 22)) ^
        ((x << 18) | (x >> 14)) ^ ((x << 24) | (x >> 8));
}

// 线性变换L'（密钥扩展用）
uint32_t SM4::L_prime(uint32_t x) {
    return x ^ ((x << 13) | (x >> 19)) ^ ((x << 23) | (x >> 9));
}

// 轮函数F
uint32_t SM4::F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    uint32_t t = x0 ^ x1 ^ x2 ^ x3 ^ rk;
    t = tau(t);  // 非线性变换
    return L(t); // 线性变换
}

// 构造函数：密钥扩展
SM4::SM4(const std::vector<uint8_t>& key) {
    if (key.size() != 16) {
        throw std::invalid_argument("SM4 key must be 16 bytes");
    }

    // 密钥拆分为4个32位字
    uint32_t k[36];
    for (int i = 0; i < 4; ++i) {
        k[i] = put_uint32(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]) ^ FK[i];
    }

    // 生成32个轮密钥
    for (int i = 0; i < 32; ++i) {
        k[i + 4] = k[i] ^ L_prime(tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
        rk[i] = k[i + 4];
    }
}

// 加密函数
void SM4::encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) {
    if (plaintext.size() != 16 || ciphertext.size() != 16) {
        throw std::invalid_argument("SM4 plaintext/ciphertext must be 16 bytes");
    }

    // 明文拆分为4个32位字
    uint32_t x[4];
    for (int i = 0; i < 4; ++i) {
        x[i] = put_uint32(plaintext[4 * i], plaintext[4 * i + 1], plaintext[4 * i + 2], plaintext[4 * i + 3]);
    }

    // 32轮迭代
    for (int i = 0; i < 32; ++i) {
        uint32_t x4 = F(x[0], x[1], x[2], x[3], rk[i]);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = x4;
    }

    // 反序变换并输出密文
    for (int i = 0; i < 4; ++i) {
        uint32_t val = x[3 - i];
        ciphertext[4 * i] = get_uint8(val, 0);
        ciphertext[4 * i + 1] = get_uint8(val, 1);
        ciphertext[4 * i + 2] = get_uint8(val, 2);
        ciphertext[4 * i + 3] = get_uint8(val, 3);
    }
}

// 解密函数（轮密钥逆序使用）
void SM4::decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext) {
    if (ciphertext.size() != 16 || plaintext.size() != 16) {
        throw std::invalid_argument("SM4 ciphertext/plaintext must be 16 bytes");
    }

    // 密文拆分为4个32位字
    uint32_t x[4];
    for (int i = 0; i < 4; ++i) {
        x[i] = put_uint32(ciphertext[4 * i], ciphertext[4 * i + 1], ciphertext[4 * i + 2], ciphertext[4 * i + 3]);
    }

    // 32轮迭代（轮密钥逆序）
    for (int i = 0; i < 32; ++i) {
        uint32_t x4 = F(x[0], x[1], x[2], x[3], rk[31 - i]);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = x4;
    }

    // 反序变换并输出明文
    for (int i = 0; i < 4; ++i) {
        uint32_t val = x[3 - i];
        plaintext[4 * i] = get_uint8(val, 0);
        plaintext[4 * i + 1] = get_uint8(val, 1);
        plaintext[4 * i + 2] = get_uint8(val, 2);
        plaintext[4 * i + 3] = get_uint8(val, 3);
    }
}

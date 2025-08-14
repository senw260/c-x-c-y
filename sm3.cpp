#include "sm3.h"

// 初始哈希值IV (GB/T 32905-2016规定)
const uint32_t SM3::IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// 常量T_j定义
const uint32_t SM3::T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// 构造函数: 初始化状态
SM3::SM3() {
    memcpy(state, IV, sizeof(IV));
    totalBits = 0;
    bufferSize = 0;
    memset(buffer, 0, sizeof(buffer));
}

// 循环左移: 优化实现(使用位运算直接计算)
uint32_t SM3::rotateLeft(uint32_t x, int n) {
    n %= 32;
    return (x << n) | (x >> (32 - n));
}

// 置换函数P0: P0(x) = x ^ (x << 9) ^ (x << 17)
uint32_t SM3::P0(uint32_t x) {
    return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17);
}

// 置换函数P1: P1(x) = x ^ (x << 15) ^ (x << 23)
uint32_t SM3::P1(uint32_t x) {
    return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23);
}

// 布尔函数FF_j: 0-15轮用异或, 16-63轮用与或组合
uint32_t SM3::FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j <= 15) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | (x & z) | (y & z);
    }
}

// 布尔函数GG_j: 0-15轮用异或, 16-63轮用选择函数
uint32_t SM3::GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j <= 15) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | (~x & z);
    }
}

// 压缩函数: 处理512bit消息块(核心优化部分)
void SM3::compress(const uint8_t* block) {
    // 1. 消息扩展: 将512bit块扩展为68个32bit字W和64个32bit字W'
    uint32_t W[68], W1[64];

    // 优化: 一次性完成字节序转换(小端转大端)
    for (int i = 0; i < 16; ++i) {
        W[i] = (uint32_t)block[4 * i] << 24 |
            (uint32_t)block[4 * i + 1] << 16 |
            (uint32_t)block[4 * i + 2] << 8 |
            (uint32_t)block[4 * i + 3];
    }

    // 扩展W[16..67]
    for (int j = 16; j < 68; ++j) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotateLeft(W[j - 3], 15)) ^
            rotateLeft(W[j - 13], 7) ^ W[j - 6];
    }

    // 计算W'[0..63]
    for (int j = 0; j < 64; ++j) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 2. 初始化8个工作寄存器
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    // 3. 64轮迭代: 优化版(循环展开+减少重复计算)
    for (int j = 0; j < 64; ++j) {
        // 优化: 预计算常量移位值
        uint32_t Tj = T[j];
        uint32_t shiftT = rotateLeft(Tj, j);

        // 计算SS1和SS2
        uint32_t SS1 = rotateLeft(rotateLeft(A, 12) + E + shiftT, 7);
        uint32_t SS2 = SS1 ^ rotateLeft(A, 12);

        // 计算TT1和TT2
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        // 更新寄存器(优化: 减少临时变量)
        D = C;
        C = rotateLeft(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rotateLeft(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 4. 状态更新
    state[0] ^= A;
    state[1] ^= B;
    state[2] ^= C;
    state[3] ^= D;
    state[4] ^= E;
    state[5] ^= F;
    state[6] ^= G;
    state[7] ^= H;
}

// 更新消息: 处理输入数据(支持分块输入)
void SM3::update(const uint8_t* data, size_t len) {
    totalBits += len * 8;  // 更新总长度(bit)

    // 处理缓存区已有数据
    if (bufferSize > 0) {
        size_t fill = 64 - bufferSize;
        if (len <= fill) {
            memcpy(buffer + bufferSize, data, len);
            bufferSize += len;
            return;  // 缓存区未满, 无需压缩
        }
        else {
            memcpy(buffer + bufferSize, data, fill);
            compress(buffer);  // 处理满的块
            data += fill;
            len -= fill;
            bufferSize = 0;
        }
    }

    // 处理完整的块
    while (len >= 64) {
        compress(data);
        data += 64;
        len -= 64;
    }

    // 剩余数据存入缓存区
    if (len > 0) {
        memcpy(buffer, data, len);
        bufferSize = len;
    }
}

// 字符串版本的update
void SM3::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// 完成计算: 处理填充并生成哈希值
void SM3::final(uint8_t* hash) {
    // 1. 填充消息
    buffer[bufferSize++] = 0x80;  // 添加1个"1"比特

    // 如果剩余空间不足8字节(存储长度), 先处理一个块
    if (bufferSize > 56) {
        memset(buffer + bufferSize, 0, 64 - bufferSize);
        compress(buffer);
        bufferSize = 0;
    }

    // 填充0直到长度为56字节
    memset(buffer + bufferSize, 0, 56 - bufferSize);
    bufferSize = 56;

    // 添加64位消息总长度(大端模式)
    uint64_t bits = totalBits;
    for (int i = 0; i < 8; ++i) {
        buffer[bufferSize++] = (uint8_t)(bits >> (8 * (7 - i)));
    }

    // 处理最后一个块
    compress(buffer);

    // 2. 输出哈希值(大端模式)
    for (int i = 0; i < 8; ++i) {
        hash[4 * i] = (uint8_t)(state[i] >> 24);
        hash[4 * i + 1] = (uint8_t)(state[i] >> 16);
        hash[4 * i + 2] = (uint8_t)(state[i] >> 8);
        hash[4 * i + 3] = (uint8_t)state[i];
    }
}

// 返回字符串形式的哈希值
std::string SM3::final() {
    uint8_t hash[32];
    final(hash);

    // 转换为16进制字符串
    static const char* hex = "0123456789abcdef";
    std::string res;
    res.reserve(64);
    for (uint8_t b : hash) {
        res += hex[b >> 4];
        res += hex[b & 0x0f];
    }
    return res;
}

// 便捷接口: 直接计算字符串的哈希值
std::string SM3::hash(const std::string& data) {
    SM3 sm3;
    sm3.update(data);
    return sm3.final();
}

// 便捷接口: 直接计算字节数组的哈希值
void SM3::hash(const uint8_t* data, size_t len, uint8_t* hash) {
    SM3 sm3;
    sm3.update(data, len);
    sm3.final(hash);
}

#include "sm3.h"

// ��ʼ��ϣֵIV (GB/T 32905-2016�涨)
const uint32_t SM3::IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// ����T_j����
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

// ���캯��: ��ʼ��״̬
SM3::SM3() {
    memcpy(state, IV, sizeof(IV));
    totalBits = 0;
    bufferSize = 0;
    memset(buffer, 0, sizeof(buffer));
}

// ѭ������: �Ż�ʵ��(ʹ��λ����ֱ�Ӽ���)
uint32_t SM3::rotateLeft(uint32_t x, int n) {
    n %= 32;
    return (x << n) | (x >> (32 - n));
}

// �û�����P0: P0(x) = x ^ (x << 9) ^ (x << 17)
uint32_t SM3::P0(uint32_t x) {
    return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17);
}

// �û�����P1: P1(x) = x ^ (x << 15) ^ (x << 23)
uint32_t SM3::P1(uint32_t x) {
    return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23);
}

// ��������FF_j: 0-15�������, 16-63����������
uint32_t SM3::FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j <= 15) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | (x & z) | (y & z);
    }
}

// ��������GG_j: 0-15�������, 16-63����ѡ����
uint32_t SM3::GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j <= 15) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | (~x & z);
    }
}

// ѹ������: ����512bit��Ϣ��(�����Ż�����)
void SM3::compress(const uint8_t* block) {
    // 1. ��Ϣ��չ: ��512bit����չΪ68��32bit��W��64��32bit��W'
    uint32_t W[68], W1[64];

    // �Ż�: һ��������ֽ���ת��(С��ת���)
    for (int i = 0; i < 16; ++i) {
        W[i] = (uint32_t)block[4 * i] << 24 |
            (uint32_t)block[4 * i + 1] << 16 |
            (uint32_t)block[4 * i + 2] << 8 |
            (uint32_t)block[4 * i + 3];
    }

    // ��չW[16..67]
    for (int j = 16; j < 68; ++j) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotateLeft(W[j - 3], 15)) ^
            rotateLeft(W[j - 13], 7) ^ W[j - 6];
    }

    // ����W'[0..63]
    for (int j = 0; j < 64; ++j) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 2. ��ʼ��8�������Ĵ���
    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    // 3. 64�ֵ���: �Ż���(ѭ��չ��+�����ظ�����)
    for (int j = 0; j < 64; ++j) {
        // �Ż�: Ԥ���㳣����λֵ
        uint32_t Tj = T[j];
        uint32_t shiftT = rotateLeft(Tj, j);

        // ����SS1��SS2
        uint32_t SS1 = rotateLeft(rotateLeft(A, 12) + E + shiftT, 7);
        uint32_t SS2 = SS1 ^ rotateLeft(A, 12);

        // ����TT1��TT2
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        // ���¼Ĵ���(�Ż�: ������ʱ����)
        D = C;
        C = rotateLeft(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rotateLeft(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 4. ״̬����
    state[0] ^= A;
    state[1] ^= B;
    state[2] ^= C;
    state[3] ^= D;
    state[4] ^= E;
    state[5] ^= F;
    state[6] ^= G;
    state[7] ^= H;
}

// ������Ϣ: ������������(֧�ַֿ�����)
void SM3::update(const uint8_t* data, size_t len) {
    totalBits += len * 8;  // �����ܳ���(bit)

    // ����������������
    if (bufferSize > 0) {
        size_t fill = 64 - bufferSize;
        if (len <= fill) {
            memcpy(buffer + bufferSize, data, len);
            bufferSize += len;
            return;  // ������δ��, ����ѹ��
        }
        else {
            memcpy(buffer + bufferSize, data, fill);
            compress(buffer);  // �������Ŀ�
            data += fill;
            len -= fill;
            bufferSize = 0;
        }
    }

    // ���������Ŀ�
    while (len >= 64) {
        compress(data);
        data += 64;
        len -= 64;
    }

    // ʣ�����ݴ��뻺����
    if (len > 0) {
        memcpy(buffer, data, len);
        bufferSize = len;
    }
}

// �ַ����汾��update
void SM3::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ��ɼ���: ������䲢���ɹ�ϣֵ
void SM3::final(uint8_t* hash) {
    // 1. �����Ϣ
    buffer[bufferSize++] = 0x80;  // ���1��"1"����

    // ���ʣ��ռ䲻��8�ֽ�(�洢����), �ȴ���һ����
    if (bufferSize > 56) {
        memset(buffer + bufferSize, 0, 64 - bufferSize);
        compress(buffer);
        bufferSize = 0;
    }

    // ���0ֱ������Ϊ56�ֽ�
    memset(buffer + bufferSize, 0, 56 - bufferSize);
    bufferSize = 56;

    // ���64λ��Ϣ�ܳ���(���ģʽ)
    uint64_t bits = totalBits;
    for (int i = 0; i < 8; ++i) {
        buffer[bufferSize++] = (uint8_t)(bits >> (8 * (7 - i)));
    }

    // �������һ����
    compress(buffer);

    // 2. �����ϣֵ(���ģʽ)
    for (int i = 0; i < 8; ++i) {
        hash[4 * i] = (uint8_t)(state[i] >> 24);
        hash[4 * i + 1] = (uint8_t)(state[i] >> 16);
        hash[4 * i + 2] = (uint8_t)(state[i] >> 8);
        hash[4 * i + 3] = (uint8_t)state[i];
    }
}

// �����ַ�����ʽ�Ĺ�ϣֵ
std::string SM3::final() {
    uint8_t hash[32];
    final(hash);

    // ת��Ϊ16�����ַ���
    static const char* hex = "0123456789abcdef";
    std::string res;
    res.reserve(64);
    for (uint8_t b : hash) {
        res += hex[b >> 4];
        res += hex[b & 0x0f];
    }
    return res;
}

// ��ݽӿ�: ֱ�Ӽ����ַ����Ĺ�ϣֵ
std::string SM3::hash(const std::string& data) {
    SM3 sm3;
    sm3.update(data);
    return sm3.final();
}

// ��ݽӿ�: ֱ�Ӽ����ֽ�����Ĺ�ϣֵ
void SM3::hash(const uint8_t* data, size_t len, uint8_t* hash) {
    SM3 sm3;
    sm3.update(data, len);
    sm3.final(hash);
}

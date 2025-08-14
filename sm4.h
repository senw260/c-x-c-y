#ifndef SM4_H
#define SM4_H

#include <vector>
#include <cstdint>

class SM4 {
private:
    // S�У����궨�壩
    static const uint8_t Sbox[256];
    // �̶�����FK��CK
    static const uint32_t FK[4];
    static const uint32_t CK[32];
    // ����Կ��32����
    uint32_t rk[32];

    // �����������ֽڲ����ϲ�
    static uint8_t get_uint8(uint32_t x, int i);
    static uint32_t put_uint32(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3);

    // �����Ա任����Կ��չ�ã�
    static uint32_t tau(uint32_t x);
    // ���Ա任L�������ã�
    static uint32_t L(uint32_t x);
    // ���Ա任L'����Կ��չ�ã�
    static uint32_t L_prime(uint32_t x);
    // �ֺ���
    static uint32_t F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk);

public:
    // ���캯��������128λ��Կ��16�ֽڣ�
    SM4(const std::vector<uint8_t>& key);

    // ���ܣ�����16�ֽ����ģ����16�ֽ�����
    void encrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext);

    // ���ܣ�����16�ֽ����ģ����16�ֽ�����
    void decrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& plaintext);
};

#endif // SM4_H

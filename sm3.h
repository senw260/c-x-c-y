#ifndef SM3_H
#define SM3_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

// SM3�㷨ʵ����
class SM3 {
private:
    // ��ʼ��ϣֵIV
    static const uint32_t IV[8];
    // ����T_j (0-15��: 0x79cc4519, 16-63��: 0x7a879d8a)
    static const uint32_t T[64];

    // 8��״̬�Ĵ���
    uint32_t state[8];
    // ��Ϣ�ܳ���(bit)
    uint64_t totalBits;
    // ������(���64�ֽ�)
    uint8_t buffer[64];
    // ��������ʹ���ֽ���
    size_t bufferSize;

    // ��������: ѭ������
    static uint32_t rotateLeft(uint32_t x, int n);

    // �û�����P0
    static uint32_t P0(uint32_t x);

    // �û�����P1
    static uint32_t P1(uint32_t x);

    // ��������FF_j
    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j);

    // ��������GG_j
    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j);

    // ѹ������: ����һ��512bit��Ϣ��
    void compress(const uint8_t* block);

public:
    // ���캯��: ��ʼ��״̬
    SM3();

    // ������Ϣ: ������������
    void update(const uint8_t* data, size_t len);
    void update(const std::string& data);

    // ��ɼ���: ����ʣ�����ݲ��������չ�ϣֵ
    void final(uint8_t* hash);
    std::string final();

    // ��ݽӿ�: ֱ�Ӽ������ݵĹ�ϣֵ
    static std::string hash(const std::string& data);
    static void hash(const uint8_t* data, size_t len, uint8_t* hash);
};

#endif // SM3_H
#pragma once

#include "sm4.h"
#include <iostream>
#include <iomanip>

// ��ӡ�ֽ����飨ʮ�����ƣ�
void print_bytes(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << ": ";
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // ��������������ʾ����
    std::vector<uint8_t> key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    std::vector<uint8_t> plaintext = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    std::vector<uint8_t> ciphertext(16);
    std::vector<uint8_t> decrypted(16);

    try {
        // ����SM4ʵ������ʼ����Կ��
        SM4 sm4(key);

        // ����
        sm4.encrypt(plaintext, ciphertext);
        // ����
        sm4.decrypt(ciphertext, decrypted);

        // ��ӡ���
        print_bytes(plaintext, "Plaintext ");
        print_bytes(ciphertext, "Ciphertext");
        print_bytes(decrypted, "Decrypted ");

        // ��֤�����Ƿ���ȷ
        if (decrypted == plaintext) {
            std::cout << "Test passed: Decrypted text matches plaintext" << std::endl;
        }
        else {
            std::cout << "Test failed: Decrypted text does not match plaintext" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

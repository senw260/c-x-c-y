#include "sm4.h"
#include <iostream>
#include <iomanip>

// 打印字节数组（十六进制）
void print_bytes(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << ": ";
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // 测试向量（国标示例）
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
        // 创建SM4实例（初始化密钥）
        SM4 sm4(key);

        // 加密
        sm4.encrypt(plaintext, ciphertext);
        // 解密
        sm4.decrypt(ciphertext, decrypted);

        // 打印结果
        print_bytes(plaintext, "Plaintext ");
        print_bytes(ciphertext, "Ciphertext");
        print_bytes(decrypted, "Decrypted ");

        // 验证解密是否正确
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

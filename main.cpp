#include "password_checkup.h"
#include <iostream>
#include <vector>

int main() {
    // 1. ׼��һЩģ���й¶����
    std::vector<std::string> leakedPasswords = {
        "password123",
        "qwerty",
        "123456",
        "letmein",
        "secret"
    };

    // 2. ���������ɲ�¡������
    std::vector<bool> bloomFilter = generateLeakedPasswordsBloomFilter(leakedPasswords);
    std::cout << "�������ѳ�ʼ������¡��������С: " << bloomFilter.size() << std::endl;

    // 3. �����ͻ��˺ͷ�����ʵ��
    PasswordCheckup client;
    PasswordCheckup server;

    // 4. ���Լ�������
    std::vector<std::string> testPasswords = {
        "password123",  // Ӧ�ñ���⵽����й¶�б��У�
        "mypassword",   // ��Ӧ�ñ���⵽
        "qwerty",       // Ӧ�ñ���⵽
        "secure123!"    // ��Ӧ�ñ���⵽
    };

    for (const std::string& password : testPasswords) {
        std::cout << "\n�������: " << password << std::endl;

        // �ͻ���׼������
        auto [clientHashXorR, clientHashes] = client.clientPrepare(password);

        // ��������������
        std::vector<bool> serverResponse = server.serverProcess(clientHashXorR, clientHashes, bloomFilter);

        // �ͻ�����֤���
        std::string passwordHash = client.sha256(password);
        std::vector<int> indices = client.hashFunctions(passwordHash);
        bool isLeaked = client.clientVerify(serverResponse, indices);

        if (isLeaked) {
            std::cout << "����: ��������������й¶�б����֣�" << std::endl;
        }
        else {
            std::cout << "��ȫ: ������δ����֪����й¶�з��֡�" << std::endl;
        }
    }

    return 0;
}

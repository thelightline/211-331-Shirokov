
#include <cstdio>
#include <iostream>
#include <tchar.h>
#include "sgx_urts.h" // вместо #include <string.h>
#include "sgx_tseal.h"
#include "Lab3_Enclave_u.h"
#define ENCLAVE_FILE _T("C:\\Users\\waveform\\Desktop\\proga\\LR3_Shirokov\\Lab3_Client\\x64\\Simulation\\Lab3_Enclave.signed.dll")

int main() {
    /* 1. Активация анклава */
    sgx_enclave_id_t eid;
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = { 0 };
    int updated = 0;

    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("App: error %#x, failed to create enclave.\n", ret);
        return -1;
    }

    /* 2. Работа с данными, ввод/вывод из этапа */
    int index;
    while (true) {
        std::cout << "Enter the index of elemet: ";
        if ((std::cin >> index)) {
            char buffer[180];
            memset(buffer, 0, 180);
            get_elem(eid, buffer, 180, index);
            printf("%s\n\n", buffer);
        }
        else {
            std::cout << "Error: Data type error\n\n";
            return 0;
        }
    }

    /* 3. Выгрузить анклава */
    if (SGX_SUCCESS != sgx_destroy_enclave(eid))
        return -1;
    return 0;
}
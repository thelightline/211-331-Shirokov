#include "Lab3_Enclave_t.h"
#include <string.h>
#include "sgx_trts.h"

const int db_size = 10;
const char* db_arr[db_size] = { "+7 (916) 123-45-67", "+7 (911) 987-65-43", "+7 (383) 555-22-11", "+7 (343) 333-44-55", "+7 (843) 765-43-21", "+7 (846) 444-12-98", "+7 (381) 222-66-77", "+7 (863) 555-77-88", "+7 (347) 777-33-22", "+7 (423) 123-88-99"};
const char error[] = "Element does not exist!";

void get_elem(char* buffer, int len, int index) {

    if (index >= db_size || index < 0) {
        memcpy(buffer, error, strlen(error));
    }
    else
    {
        memcpy(buffer, db_arr[index], strlen(db_arr[index]));
    }

}
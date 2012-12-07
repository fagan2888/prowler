#include <stdio.h>
#include <stdlib.h>
#include "prowl.h"

int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: prowler <source> <priority-number> <event> <description>\n");
        return 2;
    }

    int result = prowl_push_msg(API_KEY, atoi(argv[2]), argv[1], argv[3], argv[4]);

    return (result == 200) ? 0 : 1;
}

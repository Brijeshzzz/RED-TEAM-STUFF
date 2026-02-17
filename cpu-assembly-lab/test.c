#include <stdio.h>

int add(int a, int b) {
    int c = a + b;
    return c;
}

int main() {
    int result = add(5, 10);
    printf("Result %d\n", result);
    return 0;
}

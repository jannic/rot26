#include </home/jD91mZM2/Coding/Rust/rot26/c_header.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char* encrypted = rot26_encrypt("hello");
    puts(encrypted);

    rot26_free(encrypted);
}

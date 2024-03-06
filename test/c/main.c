#include "cart.h"
#include <string.h>

int main(char** argv, int argn) {

    // Read in our input file
    FILE * input_file = fopen("./cart.h", "rb");
    char* input = malloc(10 << 20);
    size_t input_size = fread(input, 1, 10 << 20, input_file);
    input[input_size] = '\0';
    if(input_size == 0){
        return 15;
    }

    // ------------------------------------------------------------------------
    // Test the file base input/ouput

    // Encode file
    if(CART_NO_ERROR != cart_pack_file_default("./cart.h", "./cart.h.cart", "{\"hello\": \"world\"}")) {
        return 1;
    }

    // Decode file
    CartUnpackResult result = cart_unpack_file("./cart.h.cart", "./cart_copy.h");
    if(result.error != CART_NO_ERROR) {
        return 2;
    }

    // printf("%li %li %li\n", result.body_size, result.header_json_size, result.footer_json_size);
    // printf("%d %d %d\n", result.body != 0, result.header_json != 0, result.footer_json != 0);

    FILE * output_file = fopen("./cart_copy.h", "rb");
    char* output = malloc(10 << 20);
    size_t output_size = fread(output, 1, 10 << 20, output_file);
    output[output_size] = '\0';

    if(strcmp(input, output) != 0) {
        return 3;
    }
    if(strcmp(result.header_json, "{\"hello\":\"world\"}") != 0) {
        printf("%s", result.header_json);
        return 4;
    }

    cart_free_unpack_result(result);

    // ------------------------------------------------------------------------
    // Test the buffer based input/ouput

    // Encode file
    CartPackResult pack_result = cart_pack_data_default(input, input_size, "{\"hello\": \"world\"}");
    if(pack_result.error != CART_NO_ERROR) {
        return 5;
    }

    // Decode file
    result = cart_unpack_data(pack_result.packed, pack_result.packed_size);
    if(result.error != CART_NO_ERROR) {
        return 6;
    }

    // printf("%li %li %li\n", result.body_size, result.header_json_size, result.footer_json_size);
    // printf("%d %d %d\n", result.body != 0, result.header_json != 0, result.footer_json != 0);

    cart_free_pack_result(pack_result);

    if(input_size != result.body_size) {
        return 7;
    }

    if(strncmp(input, result.body, input_size) != 0) {
        return 8;
    }
    if(strcmp(result.header_json, "{\"hello\":\"world\"}") != 0) {
        printf("%s", result.header_json);
        return 9;
    }

    cart_free_unpack_result(result);

    return 0;
}


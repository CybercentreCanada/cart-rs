#include "cart.h"
#include <string.h>

int main(char** argv, int argn) {
    // A file to encode
    char* input_file = "./cart.h";
    char* metadata_json = "{\"hello\": \"world\"}";
    char* carted_file = "./cart.h.cart";
    char* output_file = "./cart_copy.h";

    // Encode file
    if(CART_NO_ERROR != cart_pack_file_default(input_file, carted_file, metadata_json)) {
        return 1;
    }

    // Decode file
    CartUnpackResult result = cart_unpack_file(carted_file, output_file);
    if(result.error != CART_NO_ERROR) {
        return 2;
    }

    cart_free_unpack_result(result);
}
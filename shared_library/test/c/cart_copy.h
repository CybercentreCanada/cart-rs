#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * Error code set when a call completes without errors
 */
#define CART_NO_ERROR 0

/**
 * Error code when a string argument could not be parsed
 */
#define CART_ERROR_BAD_ARGUMENT_STR 1

/**
 * Error code when an input file could not be opened
 */
#define CART_ERROR_OPEN_FILE_READ 2

/**
 * Error code when an output file could not be opened
 */
#define CART_ERROR_OPEN_FILE_WRITE 3

/**
 * Error code when input json could not be parsed
 */
#define CART_ERROR_BAD_JSON_ARGUMENT 5

/**
 * Error code when an unexpected null argument was passed
 */
#define CART_ERROR_NULL_ARGUMENT 7

/**
 * Error code when an error occurs processing the input data
 */
#define CART_ERROR_PROCESSING 6

/**
 * A struct returned from encoding functions that may return a buffer.
 *
 * The buffer `packed` should only be set if the `error` field is set to [CART_NO_ERROR].
 * Buffers behind this structure can be released using the [cart_free_pack_result] function.
 */
typedef struct CartPackResult {
  uint32_t error;
  uint8_t *packed;
  uint64_t packed_size;
} CartPackResult;

/**
 * A struct returned from decoding functions that may return a buffer.
 *
 * Which buffers have a value depends on the semantics of the function returning it.
 * Buffers should only be set if the `error` field is set to [CART_NO_ERROR].
 * Buffers behind this structure can be released using the [cart_free_unpack_result] function.
 */
typedef struct CartUnpackResult {
  uint32_t error;
  uint8_t *body;
  uint64_t body_size;
  uint8_t *header_json;
  uint64_t header_json_size;
  uint8_t *footer_json;
  uint64_t footer_json_size;
} CartUnpackResult;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Cart encode a file from disk into a new file.
 *
 * Encode a file in the cart format using default parameters for all optional parameters.
 * The output file will be truncated if it already exists.
 * The header json should be a json encoded string with a mapping of key value pairs.
 */
uint32_t cart_pack_file_default(const char *input_path,
                                const char *output_path,
                                const char *header_json);

/**
 * Cart encode between open libc file handles.
 *
 * Encode a file in the cart format using default parameters for all optional parameters.
 * The input handle must be open for reading, the output handle must be open for writing.
 * The header json should be a json encoded string with a mapping of key value pairs.
 */
uint32_t cart_pack_stream_default(FILE *input_stream, FILE *output_stream, const char *header_json);

/**
 * Cart encode a buffer.
 *
 * Encode a file in the cart format using default parameters for all optional parameters.
 * The header json should be a json encoded string with a mapping of key value pairs.
 */
struct CartPackResult cart_pack_data_default(const char *input_buffer,
                                             uintptr_t input_buffer_size,
                                             const char *header_json);

/**
 * Decode a cart encoded file into a new file.
 *
 * The decoded file body is written to the output file and is not set the returned struct.
 * The output file will be truncated if it already exists.
 */
struct CartUnpackResult cart_unpack_file(const char *input_path, const char *output_path);

/**
 * Decode cart data from an open libc file into another.
 *
 * The decoded file body is written to the output and is not set the returned struct.
 * The input handle must be open for reading, the output handle must be open for writing.
 */
struct CartUnpackResult cart_unpack_stream(FILE *input_stream, FILE *output_stream);

/**
 * Decode cart data from a buffer.
 */
struct CartUnpackResult cart_unpack_data(const char *input_buffer, uintptr_t input_buffer_size);

/**
 * Test if the file at a given path contains cart data.
 */
bool cart_is_file_cart(const char *input_path);

/**
 * Test if the given file object contains cart data.
 *
 * The file handle is read from and is not reset to its original location.
 */
bool cart_is_stream_cart(FILE *stream);

/**
 * Test if the given buffer contains cart data.
 */
bool cart_is_data_cart(const char *data, uintptr_t data_size);

/**
 * Open the cart file at the given path and read out its metadata.
 *
 * In the returned struct only the header buffer will contain data.
 */
struct CartUnpackResult cart_get_file_metadata_only(const char *input_path);

/**
 * Read header metadata only from a cart file object.
 *
 * In the returned struct only the header buffer will contain data.
 */
struct CartUnpackResult cart_get_stream_metadata_only(FILE *stream);

/**
 * Read header metadata only from a buffer of cart data.
 *
 * In the returned struct only the header buffer will contain data.
 */
struct CartUnpackResult cart_get_data_metadata_only(const char *data, uintptr_t data_size);

/**
 * Release any resources behind a [CartUnpackResult] struct.
 *
 * This function should be safe to call even if the struct has no data.
 * This function should be safe to call repeatedly on the same struct.
 */
void cart_free_unpack_result(struct CartUnpackResult buf);

/**
 * Release any resources behind a [CartPackResult] struct.
 *
 * This function should be safe to call even if the struct has no data.
 * This function should be safe to call repeatedly on the same struct.
 */
void cart_free_pack_result(struct CartPackResult buf);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

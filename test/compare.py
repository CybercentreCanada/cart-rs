import ctypes
import tempfile
import json
import os.path

import cart

HERE = os.path.dirname(__file__)


class CartUnpackResult(ctypes.Structure):
    _fields_ = [
        ("error", ctypes.c_uint32),
        ("body", ctypes.POINTER(ctypes.c_uint8)),
        ("body_size", ctypes.c_uint64),
        ("header_json", ctypes.POINTER(ctypes.c_uint8)),
        ("header_json_size", ctypes.c_uint64),
        ("footer_json", ctypes.POINTER(ctypes.c_uint8)),
        ("footer_json_size", ctypes.c_uint64),
    ]


def roundtrip(lib):
    temp = tempfile.NamedTemporaryFile('wb')
    out = tempfile.NamedTemporaryFile('rb')
    metadata = {"hello": "world"}

    assert lib.cart_pack_file_default("/bin/bash".encode(), temp.name.encode(),
                                      json.dumps(metadata).encode()) == 0
    resp = lib.cart_unpack_file(temp.name.encode(), out.name.encode())
    assert resp.error == 0, resp.error
    assert json.loads(bytes(resp.header_json[0:resp.header_json_size-1])) == metadata
    lib.cart_free_unpack_result(resp)

    with open("/bin/bash", 'rb') as handle:
        original = handle.read()

    assert original == out.read()


def rust_py(lib):
    temp = tempfile.NamedTemporaryFile('wb')
    out = tempfile.NamedTemporaryFile('rb')

    assert lib.cart_pack_file_default("/bin/bash".encode(), temp.name.encode(), 0) == 0
    cart.unpack_file(temp.name, out.name)

    with open("/bin/bash", 'rb') as handle:
        original = handle.read()

    assert original == out.read()


def py_rust(lib):
    temp = tempfile.NamedTemporaryFile('wb')
    out = tempfile.NamedTemporaryFile('rb')
    metadata = {"hello": "world"}

    cart.pack_file("/bin/bash", temp.name, metadata)
    resp = lib.cart_unpack_file(temp.name.encode(), out.name.encode())
    assert resp.error == 0, resp.error
    assert json.loads(bytes(resp.header_json[0:resp.header_json_size-1])) == metadata
    lib.cart_free_unpack_result(resp)

    with open("/bin/bash", 'rb') as handle:
        original = handle.read()

    assert original == out.read()


if __name__ == '__main__':
    lib = ctypes.cdll.LoadLibrary(os.path.join(HERE, "../target/release/libcart.so"))
    lib.cart_unpack_file.restype = CartUnpackResult

    roundtrip(lib)
    rust_py(lib)
    py_rust(lib)

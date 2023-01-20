import ctypes
import tempfile
import time
import json

import cart


def roundtrip(lib):
    temp = tempfile.NamedTemporaryFile('wb')
    out = tempfile.NamedTemporaryFile('rb')

    assert lib.ccart_pack_file_default("/bin/bash".encode(), temp.name.encode(), json.dumps({"hello": "world"}).encode()) == 0
    assert lib.ccart_unpack_file(temp.name.encode(), out.name.encode()) == 0

    with open("/bin/bash", 'rb') as handle:
        original = handle.read()

    assert original == out.read()


def rust_py(lib):
    temp = tempfile.NamedTemporaryFile('wb')
    out = tempfile.NamedTemporaryFile('rb')

    _a = time.time()
    assert lib.cart_pack_file_default("/bin/bash".encode(), temp.name.encode(), 0) == 0
    _b = time.time()
    cart.unpack_file(temp.name, out.name)
    _c = time.time()

    with open("/bin/bash", 'rb') as handle:
        original = handle.read()

    assert original == out.read()

    print("rust pack", _b - _a)
    print("python unpack", _c - _b)


def py_rust(lib):
    temp = tempfile.NamedTemporaryFile('wb')
    out = tempfile.NamedTemporaryFile('rb')

    _a = time.time()
    cart.pack_file("/bin/bash", temp.name)
    _b = time.time()
    assert lib.ccart_unpack_file(temp.name.encode(), out.name.encode()) == 0
    _c = time.time()

    with open("/bin/bash", 'rb') as handle:
        original = handle.read()

    assert original == out.read()

    print("python pack", _b - _a)
    print("rust unpack", _c - _b)


if __name__ == '__main__':
    lib = ctypes.cdll.LoadLibrary("../../target/release/libccart.so")
    # roundtrip(lib)
    rust_py(lib)
    # py_rust(lib)

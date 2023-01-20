# CaRT (Compressed and RC4 Transport)

The CaRT file format is used to store/transfer malware and it's associated metadata. It neuters the malware so it cannot be executed and encrypt it so anti-virus softwares cannot flag the CaRT file as malware.

## Library

This crate provides methods to encode and decode the cart format (which can be used directly) and exports them into a c library.

## Details

For more details about how the cart format is implemented or ways it can be used check [this other repository.](https://github.com/CybercentreCanada/cart)
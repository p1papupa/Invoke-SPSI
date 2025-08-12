#!/usr/bin/env python3
"""
Simple XOR file encrypter/decrypter.
Reads a raw input file, XORs its bytes with the provided key, and writes the result as a raw output file.

Usage:
    python xor_file.py -i input.raw -o output.raw -k f62f054feab9fc06424fa3a2795d7286

Arguments:
  -i, --input     Path to the input file to process.
  -o, --output    Path where the output file will be written.
  -k, --key       XOR key as a hex string (e.g., "f62f054feab9fc06424fa3a2795d7286").
"""
import argparse
import sys

def parse_hex_key(hex_str: str) -> bytes:
    """Convert a hex string to bytes."""
    hex_str = hex_str.strip().replace('0x', '').replace('"', '')
    if len(hex_str) % 2 != 0:
        raise ValueError("Key hex string must have an even number of characters.")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f"Invalid hex key: {e}")


def xor_data(data: bytes, key: bytes) -> bytes:
    """XOR each byte of data with the key (repeating the key if shorter)."""
    key_len = len(key)
    if key_len == 0:
        raise ValueError("Key must not be empty.")
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def main():
    parser = argparse.ArgumentParser(description="XOR raw file with a key and output the result.")
    parser.add_argument('-i', '--input', required=True, help='Path to input file')
    parser.add_argument('-o', '--output', required=True, help='Path to output file')
    parser.add_argument('-k', '--key', required=True, help='XOR key as hex string')
    args = parser.parse_args()

    try:
        key_bytes = parse_hex_key(args.key)
    except ValueError as ve:
        print(f"Error parsing key: {ve}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input, 'rb') as f_in:
            data = f_in.read()
    except IOError as ioe:
        print(f"Error reading input file: {ioe}", file=sys.stderr)
        sys.exit(1)

    result = xor_data(data, key_bytes)

    try:
        with open(args.output, 'wb') as f_out:
            f_out.write(result)
    except IOError as ioe:
        print(f"Error writing output file: {ioe}", file=sys.stderr)
        sys.exit(1)

    print(f"Successfully wrote XORed file to {args.output}")

if __name__ == '__main__':
    main()


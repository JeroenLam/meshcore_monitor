# Setup imports
import os, sys
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsing import *

# Define test packet
# #tno channel
test_pkts = [
    "15001b2ce79a8bb0203a270b5688448bdd94546e1f5895ca1d6b2d576e04c1febacdc73089",
    "15014c1b5b892dd560e4c3c19c27175919338263ae315895ca1d6b2d576e04c1febacdc73089",
    "15034cee671b5b892dd560e4c3c19c27175919338263ae315895ca1d6b2d576e04c1febacdc73089",
]
pkt = bytes.fromhex(test_pkts[0])

# Parse test packet
header_f, payload_type, payload = parse_mc_header(pkt)

if payload_type is not PayloadType.PAYLOAD_TYPE_GRP_TXT:
    raise Exception("Incorrect payload type for decoding!")

payload_fields = parse_payload(payload_type, payload)

print(" ================================== ")
print(payload.hex())
for key, val in payload_fields.items():
    print(f"  {key}: {val}")

# Decrypt the above message given that the key is derived as the first 16 bytes of sha256("#tno")

# Extract payload components
channel_hash = payload[0]
cipher_mac = payload[1:3]
ciphertext = payload[3:]

# Derive the channel key
channel_name = "#tno"
sha256_hash = hashlib.sha256(channel_name.encode()).digest()
channel_key = sha256_hash[:16]  # First 16 bytes for AES-128

print("\n ================================== ")
print(f"Channel Hash: {hex(channel_hash)}")
print(f"Cipher MAC: {cipher_mac.hex()}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Channel Key (first 16 bytes of SHA256('#tno')): {channel_key.hex()}")

# Decrypt the ciphertext using AES-128-ECB
# ECB mode is used for group text messages
try:
    print("\nAttempting decryption with AES-128-ECB...")
    cipher = AES.new(channel_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    print("Success with ECB mode!")

    print(f"\nDecrypted data: {decrypted.hex()}")
    print(f"Decrypted data (raw): {decrypted}")

    # Parse the decrypted message structure
    # Format: timestamp (4 bytes) + flags (1 byte) + message (remaining bytes)
    offset = 0

    # Extract timestamp (4 bytes, little-endian)
    timestamp_bytes = decrypted[offset : offset + 4]
    timestamp = int.from_bytes(timestamp_bytes, byteorder="little")
    timestamp_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    offset += 4

    # Extract flags (1 byte)
    flags = decrypted[offset]
    offset += 1

    # Extract message (remaining bytes)
    # The message may be null-terminated or contain extra padding
    message_bytes = decrypted[offset:]

    # Try to find null terminator
    null_index = message_bytes.find(b"\x00")
    if null_index != -1:
        message_bytes = message_bytes[:null_index]

    message = message_bytes.decode("utf-8", errors="replace")

    print(f"\n ================================== ")
    print(f"Timestamp: {timestamp_str} (unix: {timestamp})")
    print(f"Flags: {hex(flags)}")
    print(f"Message: {message}")

except Exception as e:
    print(f"Decryption failed: {e}")
    import traceback

    traceback.print_exc()

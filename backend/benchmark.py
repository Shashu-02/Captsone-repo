import time
import os
import crypto_engine
import ipfs_manager
import keygen

def run_benchmark(file_size_bytes, size_label):
    print(f"\n--- Running Benchmark for {size_label} ---")
    
    # 1. Generate random dummy data of the specified size
    dummy_data = os.urandom(file_size_bytes)
    
    # 2. Get AES key
    if not os.path.exists("aes_key.bin"):
        keygen.generate_aes_key()
    with open("aes_key.bin", "rb") as f:
        aes_key = f.read()
        
    # 3. Measure Cryptographic Latency (Encryption + Signing)
    start_crypto = time.time()
    encrypted_hex, iv_hex, signature_hex = crypto_engine.encrypt_and_sign(dummy_data, aes_key)
    end_crypto = time.time()
    crypto_time_ms = (end_crypto - start_crypto) * 1000
    
    # 4. Measure Storage Overhead
    payload_to_store = f"{encrypted_hex}::{iv_hex}::{signature_hex}"
    original_size = len(dummy_data)
    final_size = len(payload_to_store.encode('utf-8'))
    overhead_percent = ((final_size - original_size) / original_size) * 100
    
    # 5. Measure IPFS Upload Latency
    start_ipfs = time.time()
    cid = ipfs_manager.upload_data(payload_to_store)
    end_ipfs = time.time()
    ipfs_time_ms = (end_ipfs - start_ipfs) * 1000
    
    # Print Results for the Capstone Report
    print(f"Cryptographic Latency: {crypto_time_ms:.2f} ms")
    print(f"IPFS Upload Latency:   {ipfs_time_ms:.2f} ms")
    print(f"Original File Size:    {original_size} bytes")
    print(f"Final IPFS Size:       {final_size} bytes")
    print(f"Storage Overhead:      {overhead_percent:.2f}%")
    print(f"IPFS CID:              {cid}")

if __name__ == "__main__":
    print("Initializing ZeroTrust-Mesh Benchmarking Tool...")
    
    # Ensure SECP256K1 identity keys exist before running
    if not os.path.exists("private_key.pem"):
        print("Generating SECP256K1 Keys...")
        keygen.generate_secp256k1_keys()
        
    # Run tests for different file sizes
    run_benchmark(1024, "1 KB File")           # Small text file
    run_benchmark(500 * 1024, "500 KB File")   # Medium document
    run_benchmark(1024 * 1024, "1 MB File")    # Large dataset
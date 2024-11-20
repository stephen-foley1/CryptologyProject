import time
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size):
    start_time = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    end_time = time.time()
    return private_key, end_time - start_time

def generate_dsa_keypair(key_size):
    start_time = time.time()
    private_key = dsa.generate_private_key(
        key_size=key_size
    )
    end_time = time.time()
    return private_key, end_time - start_time

def generate_ecc_keypair(curve):
    start_time = time.time()
    private_key = ec.generate_private_key(
        curve
    )
    end_time = time.time()
    return private_key, end_time - start_time

def main():
    rsa_key_sizes = [1024, 2048, 3072, 4096]
    dsa_key_sizes = [1024, 2048, 3072]
    ecc_curves = [ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]

    print("RSA Keypair Generation Times:")
    for size in rsa_key_sizes:
        _, time_taken = generate_rsa_keypair(size)
        print(f"Key Size: {size} bits, Time: {time_taken:.4f} seconds")

    print("\nDSA Keypair Generation Times:")
    for size in dsa_key_sizes:
        _, time_taken = generate_dsa_keypair(size)
        print(f"Key Size: {size} bits, Time: {time_taken:.4f} seconds")

    print("\nECC Keypair Generation Times:")
    for curve in ecc_curves:
        _, time_taken = generate_ecc_keypair(curve)
        print(f"Curve: {curve.name}, Time: {time_taken:.4f} seconds")

if __name__ == "__main__":
    main()
import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import matplotlib.pyplot as plt

# Global Variables
iterations = 10  # Number of iterations for all operations

# Key sizes and parameters
rsa_key_sizes = [1024, 2048, 3072, 7680, 15360]
dsa_key_sizes = [1024, 2048, 3072]
ecc_curves = [
    ec.SECP192R1(),  # 80-bit security
    ec.SECP224R1(),  # 112-bit security
    ec.SECP256R1(),  # 128-bit security
    ec.SECP384R1(),  # 192-bit security
    ec.SECP521R1()   # 256-bit security
]
rsa_security_bits = [80, 112, 128, 192, 256]
dsa_security_bits = [80, 112, 128]
ecc_security_bits = [80, 112, 128, 192, 256]

# Random message for signing and encryption
message = os.urandom(10 * 1024)  # 10KB


# Utility Functions
def print_message(msg):
    print(f"\n{msg}\n" + "-" * 50)


# Keypair generation functions
def generate_rsa_keypair(key_size):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def generate_dsa_keypair(key_size):
    return dsa.generate_private_key(key_size=key_size)


def generate_ecc_keypair(curve):
    return ec.generate_private_key(curve)


# Measurement functions
def measure_keygen_time(algorithm_name, generate_function, params, iterations):
    results = []
    print_message(f"Starting {algorithm_name} keypair generation...")
    for param, security in params:
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            generate_function(param)
            end = time.perf_counter()
            times.append(end - start)
        avg_time = sum(times[1:]) / (iterations - 1)  # Ignore the first iteration
        results.append((security, avg_time))
    return results


def measure_rsa_encryption_decryption_time():
    print_message("Starting RSA encryption/decryption...")
    enc_results, dec_results = [], []
    for key_size in rsa_key_sizes:
        private_key = generate_rsa_keypair(key_size)
        public_key = private_key.public_key()

        # Determine chunk size
        chunk_size = (key_size // 8) - 2 * hashes.SHA256().digest_size - 2

        enc_times, dec_times = [], []
        for _ in range(iterations):
            # Encryption
            start = time.perf_counter()
            encrypted_chunks = rsa_encrypt(public_key, message, chunk_size)
            enc_times.append(time.perf_counter() - start)

            # Decryption
            start = time.perf_counter()
            decrypted_message = rsa_decrypt(private_key, encrypted_chunks)
            dec_times.append(time.perf_counter() - start)

            # Validate decryption
            assert message == decrypted_message, "Decryption failed!"

        enc_results.append((key_size, sum(enc_times[1:]) / (iterations - 1)))
        dec_results.append((key_size, sum(dec_times[1:]) / (iterations - 1)))
    return enc_results, dec_results


def measure_sign_verify_rsa_time(key_size, iterations):
    sign_results = []
    verify_results = []
    private_key = generate_rsa_keypair(key_size)
    for _ in range(iterations):
        # Signing
        start = time.perf_counter()
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()  # Required for RSA
        )
        sign_time = time.perf_counter() - start
        sign_results.append(sign_time)

        # Verification
        public_key = private_key.public_key()
        start = time.perf_counter()
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()  # Required for RSA
        )
        verify_time = time.perf_counter() - start
        verify_results.append(verify_time)

    avg_sign_time = sum(sign_results) / iterations
    avg_verify_time = sum(verify_results) / iterations
    return avg_sign_time, avg_verify_time


def measure_sign_verify_dsa_time(key_size, iterations):
    sign_results = []
    verify_results = []
    private_key = generate_dsa_keypair(key_size)
    for _ in range(iterations):
        # Signing
        start = time.perf_counter()
        signature = private_key.sign(message, hashes.SHA256())  # Signing with SHA256
        sign_time = time.perf_counter() - start
        sign_results.append(sign_time)

        # Verification
        public_key = private_key.public_key()
        start = time.perf_counter()
        public_key.verify(signature, message, hashes.SHA256())  # Verifying with SHA256
        verify_time = time.perf_counter() - start
        verify_results.append(verify_time)

    avg_sign_time = sum(sign_results) / iterations
    avg_verify_time = sum(verify_results) / iterations
    return avg_sign_time, avg_verify_time

def measure_sign_verify_ecc_time(curve, iterations):
    sign_results = []
    verify_results = []
    private_key = generate_ecc_keypair(curve)
    for _ in range(iterations):
        # Signing
        start = time.perf_counter()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))  # Using ECDSA with SHA256
        sign_time = time.perf_counter() - start
        sign_results.append(sign_time)

        # Verification
        public_key = private_key.public_key()
        start = time.perf_counter()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))  # Verifying with ECDSA SHA256
        verify_time = time.perf_counter() - start
        verify_results.append(verify_time)

    avg_sign_time = sum(sign_results) / iterations
    avg_verify_time = sum(verify_results) / iterations
    return avg_sign_time, avg_verify_time


# RSA encryption/decryption
def rsa_encrypt(public_key, plaintext, chunk_size):
    return [
        public_key.encrypt(
            plaintext[i:i + chunk_size],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        for i in range(0, len(plaintext), chunk_size)
    ]


def rsa_decrypt(private_key, encrypted_chunks):
    return b"".join([
        private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        for chunk in encrypted_chunks
    ])


# Plotting Functions
def plot_results(results, title, xlabel, ylabel, filename):
    plt.figure(figsize=(10, 6))
    for label, data in results.items():
        security_levels = [res[0] for res in data]
        times = [res[1] for res in data]
        plt.plot(security_levels, times, label=label, marker='o')
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.legend()
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()

def plot_sign_verify_times(rsa_results, dsa_results, ecc_results, title, xlabel, ylabel, filename):
    plt.figure(figsize=(10, 6))

    # Extracting results for RSA, DSA, and ECC
    rsa_sign = [res[0] for res in rsa_results]
    rsa_verify = [res[1] for res in rsa_results]
    dsa_sign = [res[0] for res in dsa_results]
    dsa_verify = [res[1] for res in dsa_results]
    ecc_sign = [res[0] for res in ecc_results]
    ecc_verify = [res[1] for res in ecc_results]

    # Plotting
    plt.plot(rsa_key_sizes, rsa_sign, label='RSA Signing', marker='o', color='blue')
    plt.plot(rsa_key_sizes, rsa_verify, label='RSA Verification', marker='o', color='blue', linestyle='--')

    plt.plot(dsa_key_sizes, dsa_sign, label='DSA Signing', marker='s', color='green')
    plt.plot(dsa_key_sizes, dsa_verify, label='DSA Verification', marker='s', color='green', linestyle='--')

    plt.plot(ecc_security_bits, ecc_sign, label='ECC Signing', marker='^', color='red')
    plt.plot(ecc_security_bits, ecc_verify, label='ECC Verification', marker='^', color='red', linestyle='--')

    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.legend()
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()


# Main Execution
if __name__ == "__main__":
    rsa_keygen_results = measure_keygen_time(
        "RSA", generate_rsa_keypair, zip(rsa_key_sizes, rsa_security_bits), iterations
    )
    dsa_keygen_results = measure_keygen_time(
        "DSA", generate_dsa_keypair, zip(dsa_key_sizes, dsa_security_bits), iterations
    )
    ecc_keygen_results = measure_keygen_time(
        "ECC", generate_ecc_keypair, zip(ecc_curves, ecc_security_bits), iterations
    )

    rsa_enc_results, rsa_dec_results = measure_rsa_encryption_decryption_time()
    rsa_sign_verify_results = [measure_sign_verify_rsa_time(key_size, iterations) for key_size in rsa_key_sizes]
    dsa_sign_verify_results = [measure_sign_verify_dsa_time(key_size, iterations) for key_size in dsa_key_sizes]
    ecc_sign_verify_results = [measure_sign_verify_ecc_time(curve, iterations) for curve in ecc_curves]

    # Plot all results
    plot_results(
        {
            "RSA Keygen": rsa_keygen_results,
            "DSA Keygen": dsa_keygen_results,
            "ECC Keygen": ecc_keygen_results
        },
        f"Key Generation Times ({iterations} iterations)", "Security Level (bits)", "Time (seconds)", "keygen_times1.png"
    )

    plot_results(
        {
            "RSA Encryption": rsa_enc_results,
            "RSA Decryption": rsa_dec_results
        },
        f"RSA Encryption/Decryption Times ({iterations} iterations)", "Key Size (bits)", "Time (seconds)", "rsa_enc_dec_times1.png"
    )

    plot_sign_verify_times(
        rsa_sign_verify_results, dsa_sign_verify_results, ecc_sign_verify_results,
        f"Signing and Verification Times ({iterations} iterations)", "Security Level (bits)", "Time (seconds)", "sign_verify_times1.png"
    )

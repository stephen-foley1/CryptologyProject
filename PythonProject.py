import time
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import matplotlib.pyplot as plt

# Global Variables
iterations = 2 # Number of iterations for all operations

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
message = secrets.token_bytes(10 * 1024)  # 10KB


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


def measure_sign_verify_time(generate_function, params, iterations, signing_algorithm):
    print_message("Starting Signing and Verification tests...")
    sign_results, verify_results = [], []
    for param, security in params:
        private_key = generate_function(param)
        signature_times, verification_times = [], []
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
            signature_times.append(time.perf_counter() - start)

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
            verification_times.append(time.perf_counter() - start)

        sign_results.append((security, sum(signature_times[1:]) / (iterations - 1)))
        verify_results.append((security, sum(verification_times[1:]) / (iterations - 1)))
    return sign_results, verify_results

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


# Plotting Function
def plot_results(results, title, xlabel, ylabel, filename):
    plt.figure(figsize=(10, 6))
    for label, data in results.items():
        x = [r[0] for r in data]
        y = [r[1] for r in data]
        plt.plot(x, y, label=label, marker='o')
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(filename)
    plt.show()


# Main Execution
if __name__ == "__main__":
    rsa_keygen_results = measure_keygen_time(
        "RSA",
        generate_rsa_keypair,
        zip(rsa_key_sizes, rsa_security_bits),
        iterations
    )
    dsa_keygen_results = measure_keygen_time(
        "DSA",
        generate_dsa_keypair,
        zip(dsa_key_sizes, dsa_security_bits),
        iterations
    )
    ecc_keygen_results = measure_keygen_time(
        "ECC",
        generate_ecc_keypair,
        zip(ecc_curves, ecc_security_bits),
        iterations
    )

    rsa_enc_results, rsa_dec_results = measure_rsa_encryption_decryption_time()

    rsa_sign_results, rsa_verify_results = measure_sign_verify_time(
        generate_rsa_keypair,
        zip(rsa_key_sizes, rsa_security_bits),
        iterations,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
    )

    # Plotting
    plot_results({"RSA": rsa_keygen_results, "DSA": dsa_keygen_results, "ECC": ecc_keygen_results},
                 f"Keypair Generation Times ({iterations} iterations)", "Security Level (bits)",
                 "Time (seconds)", "keygen_times.png")

    plot_results({"RSA Encryption": rsa_enc_results}, f"Encryption Times ({iterations} iterations)",
                 "Key Size (bits)", "Time (seconds)", "encryption_times.png")

    plot_results({"RSA Decryption": rsa_dec_results}, f"Decryption Times ({iterations} iterations)",
                 "Key Size (bits)", "Time (seconds)", "decryption_times.png")

    plot_results({"RSA Signing": rsa_sign_results}, f"Signing Times ({iterations} iterations)",
                 "Key Size (bits)", "Time (seconds)", "signing_times.png")

    plot_results({"RSA Verification": rsa_verify_results}, f"Verification Times ({iterations} iterations)",
                 "Key Size (bits)", "Time (seconds)", "verification_times.png")
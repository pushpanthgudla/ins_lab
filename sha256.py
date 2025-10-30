import hashlib

def sha256_hash(message):
    """Compute SHA-256 hash of the input message."""
    sha256 = hashlib.sha256()
    sha256.update(message.encode())
    return sha256.hexdigest()
# Example usage
if __name__ == "__main__":
    msg = "Hello, World!"
    print(f"SHA-256 hash of '{msg}': {sha256_hash(msg)}")

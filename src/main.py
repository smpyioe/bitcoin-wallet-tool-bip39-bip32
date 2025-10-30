import os
import hashlib
import unicodedata
import hmac
from ecdsa import SigningKey, SECP256k1

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def load_wordlist():
    with open("data/bip39_english.txt", "r", encoding="utf-8") as f:
        return [w.strip() for w in f.readlines()]


def generate_entropy(bits):
    return os.urandom(bits // 8)

def entropy_to_mnemonic(entropy: bytes, wordlist: list[str]) -> str:
    ent_bits_len = len(entropy) * 8
    checksum_len = ent_bits_len // 32

    hash_bytes = hashlib.sha256(entropy).digest()
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(ent_bits_len)
    checksum_bits = bin(int.from_bytes(hash_bytes, "big"))[2:].zfill(256)[:checksum_len]
    full_bits = bits + checksum_bits

    chunks = [full_bits[i:i + 11] for i in range(0, len(full_bits), 11)]
    indexes = [int(c, 2) for c in chunks]
    mnemonic_words = [wordlist[i] for i in indexes]
    return " ".join(mnemonic_words)


def validate_mnemonic(mnemonic, wordlist):
    words = mnemonic.strip().split()


    indexes = [wordlist.index(w) for w in words]
    bits = "".join(bin(i)[2:].zfill(11) for i in indexes)

    total_len = len(bits)
    checksum_len = total_len // 33
    entropy_len = total_len - checksum_len

    entropy_bits = bits[:entropy_len]
    checksum_bits = bits[-checksum_len:]

    entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_len // 8, "big")
    hash_bytes = hashlib.sha256(entropy_bytes).digest()
    new_checksum = bin(int.from_bytes(hash_bytes, "big"))[2:].zfill(256)[:checksum_len]

    return new_checksum == checksum_bits


def mnemonic_to_seed(mnemonic, passphrase):
    mnemonic_norm = unicodedata.normalize("NFKD", mnemonic)
    passphrase_norm = unicodedata.normalize("NFKD", passphrase)
    salt = ("mnemonic" + passphrase_norm).encode("utf-8")

    seed = hashlib.pbkdf2_hmac(
        "sha512", mnemonic_norm.encode("utf-8"), salt, 2048, dklen=64
    )
    return seed


def seed_to_master_keys(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    master_priv_int = int.from_bytes(IL, "big")
    return master_priv_int, IR

def private_to_public_compressed(priv_int):
    sk = SigningKey.from_string(priv_int.to_bytes(32, "big"), curve=SECP256k1)
    vk = sk.get_verifying_key()
    px = vk.pubkey.point.x()
    py = vk.pubkey.point.y()
    prefix = b"\x02" if (py % 2 == 0) else b"\x03"
    return prefix + px.to_bytes(32, "big")

def derive_child_private_key(parent_priv_int: int, parent_chain: bytes, index: int):
    if not (0 <= index < 2**32):
        raise ValueError("index must be 0 <= index < 2**32")
    if index >= 2**31:
        data = b"\x00" + parent_priv_int.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        parent_pub = private_to_public_compressed(parent_priv_int)
        data = parent_pub + index.to_bytes(4, "big")
    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    IL_int = int.from_bytes(IL, "big")
    if IL_int >= SECP256K1_ORDER:
        raise ValueError("IL >= curve order")
    child_priv_int = (IL_int + parent_priv_int) % SECP256K1_ORDER
    return child_priv_int, IR

def derive_path(master_priv_int: int, master_chain: bytes, path: str):
    if not path.startswith("m"):
        raise ValueError("Path must start with 'm'")
    if path == "m":
        return master_priv_int, master_chain
    parts = path.split("/")[1:]
    priv = master_priv_int
    chain = master_chain
    for p in parts:
        if p == "":
            continue
        hardened = p.endswith("'") or p.endswith("h")
        idx_str = p.rstrip("'h")
        idx = int(idx_str)
        if hardened:
            idx += 2**31
        priv, chain = derive_child_private_key(priv, chain, idx)
    return priv, chain


if __name__ == "__main__":
    print("=== BIP39 + BIP32 Wallet Generator ===")
    wordlist = load_wordlist()

    print("\n1) Generate new mnemonic")
    print("2) Import existing mnemonic")
    choice = input("\nChoose an option (1/2): ").strip()

    if choice == "1":
        entropy = generate_entropy(128)
        mnemonic = entropy_to_mnemonic(entropy, wordlist)
        print("\n--- Generated Wallet ---")
        print(f"Entropy (hex): {entropy.hex()}")
        print(f"Mnemonic: {mnemonic}")

    elif choice == "2":
        mnemonic = input("\nEnter your mnemonic phrase:\n> ").strip()
        if validate_mnemonic(mnemonic, wordlist):
            print("\n Mnemonic is valid!")
        else:
            print("\n Invalid mnemonic checksum.")
            raise SystemExit(1)
    else:
        print("Invalid choice.")
        raise SystemExit(1)

    # Common: compute seed from mnemonic
    passphrase = input("\nEnter your passphrase (optional): ").strip()
    seed = mnemonic_to_seed(mnemonic, passphrase)
    print("\n--- Derived Seed (BIP39 -> seed) ---")
    print(f"Seed (hex): {seed.hex()}")

    # BIP32: master keys
    master_priv_int, master_chain = seed_to_master_keys(seed)
    master_priv_bytes = master_priv_int.to_bytes(32, "big")
    master_pub = private_to_public_compressed(master_priv_int)
    print("\n--- BIP32 Master ---")
    print(f"Master Private Key (hex): {master_priv_bytes.hex()}")
    print(f"Master Chain Code (hex): {master_chain.hex()}")
    print(f"Master Public Key (compressed hex): {master_pub.hex()}")

    # derivation options
    print("1) Derive a key")
    print("2) Exit")
    choice = input("\nChoose an option (1/2): ").strip()
    if choice == "1":
        print("\nDerivation options:")
        print("  a) derive child by index")
        print("  b) derive by path (e.g. m/44'/0'/0'/0/0)")
        opt = input("Choose (a/b, or enter to quit): ").strip().lower()
        if opt == "a":
            idx = int(input("Enter index (0..2**32-1). For hardened, add 2**31 or use index >= 2**31): ").strip())
            child_priv, child_chain = derive_child_private_key(master_priv_int, master_chain, idx)
            child_pub = private_to_public_compressed(child_priv)
            print("\n--- Child Key ---")
            print(f"Index: {idx}")
            print(f"Child Private Key (hex): {child_priv.to_bytes(32, 'big').hex()}")
            print(f"Child Chain Code (hex): {child_chain.hex()}")
            print(f"Child Public Key (compressed hex): {child_pub.hex()}")

        elif opt == "b":
            path = input("Enter derivation path (e.g. m/44'/0'/0'/0/0): ").strip()
            derived_priv, derived_chain = derive_path(master_priv_int, master_chain, path)
            derived_pub = private_to_public_compressed(derived_priv)
            print("\n--- Derived Key ---")
            print(f"Path: {path}")
            print(f"Private Key (hex): {derived_priv.to_bytes(32, 'big').hex()}")
            print(f"Public Key (compressed hex): {derived_pub.hex()}")
            print(f"Chain Code (hex): {derived_chain.hex()}")
        else:
            print("No derivation done.")


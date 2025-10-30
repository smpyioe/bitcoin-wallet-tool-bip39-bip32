# Bitcoin Wallet Tool - BIP39 & BIP32

## Context

This tool implements Bitcoin standards **BIP39** and **BIP32** to create Bitcoin wallets.

### Features:
- Generate entropy and BIP39 mnemonic phrases
- Validate existing mnemonic phrases
- Derive master keys from a seed
- Derive child keys by index or hierarchical path

## Usage

### Requirements
Create a Python virtual environment or install the libraries directly.
For example (Linux):
```bash
python -m venv venv
source venv/bin/activate
```

Then install the dependencies:
```bash
pip install -r requirements.txt
```

### Run
```bash
python src/main.py
```

### Available options

#### 1. Generate a new wallet
- Select option `1`
- The program automatically generates a 12-word mnemonic phrase
- You can add an optional passphrase

#### 2. Import an existing wallet
- Select option `2`
- Enter your 12/24-word mnemonic phrase
- The program checks the validity of the phrase

### Key derivation

After generating/importing, you can derive child keys:

#### Option A: By index
- Enter a numeric index (0 to 2³²-1)
- For "hardened" keys, add 2³¹ to the index

#### Option B: By BIP44 path
- Format: `m/44'/0'/0'/0/1`
- `m` = master key
- `'` or `h` = hardened derivation

## Example

Run:
```bash
python src/main.py
```

```
=== BIP39 + BIP32 Wallet Generator ===

1) Generate new mnemonic
2) Import existing mnemonic

Choose an option (1/2): 1

--- Generated Wallet ---
Entropy (hex): 7e7a17d9ff515ee89f258b47f71bdbfd
Mnemonic: lazy spawn wait wrong bicycle inmate lady ramp elevator rhythm want wife

Enter your passphrase (optional): 

--- Derived Seed (BIP39 -> seed) ---
Seed (hex): 9bc2ebbf1414fe71a08eb3087924ffdc22acaab933853e989d0ea75c3c9d2bc68b64b25d1435ba3f07f74f497d2170fbfafd1d93b30b995e7a4a0fc333762a41

--- BIP32 Master ---
Master Private Key (hex): 998ce8f732ac24c368418d04723956d56f43901c3aa5eb0e25594483865fc811
Master Chain Code (hex): 9edc5b497da98ebdd5c98babae646d5f485da77f6995cabf941753197f1e86c5
Master Public Key (compressed hex): 02cdbab4ef4d57b97e3d4ce797aabb396958f89d56469bdcb2f53b657b124ffb1a
1) Derive a key
2) Exit

Choose an option (1/2): 1

Derivation options:
  a) derive child by index
  b) derive by path (e.g. m/44'/0'/0'/0/0)
Choose (a/b, or enter to quit): a
Enter index (0..2**32-1). For hardened, add 2**31 or use index >= 2**31): 1

--- Child Key ---
Index: 1
Child Private Key (hex): f0a56e1b6b1fe5f7bd21a212cf60f48093754115c1ecdf8a119c45683afa50c9
Child Chain Code (hex): d4e1e642bd39e919f0d901544d873c42d0511ca751e70c0f1c6c367fac5e97dd
Child Public Key (compressed hex): 022a815ced7c4aa48604b507a7b0b3200cd439817ef034a462829099125c8bb7e4
```
# Sigverif

an simple RSA based message signing and verification utility written in python that also utilises SHA256, RSA4096 and base64

---

## Features

- generate RSA 4096-bit keypairs.
- sign plaintext message files.
- verify signed messages.
- embedded Base64 signature blocks in messages.

---

## Installation

Clone this repository and ensure you have Python 3 installed:

```bash
git clone https://github.com/H1Hollow/sigverif.git
cd <repository_folder>
pip install -r requirements.txt
python3 src/main.py --help

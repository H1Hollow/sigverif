#// imports

import re, base64, sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#// functions

def generate_keypair(keyname):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    with open(f"private-{keyname}.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(f'public-{keyname}.pem', "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def sign_message(private_key, message_str: str) -> str:
    message = message_str.encode('utf-8')
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    message_hash = digest.finalize()

    signature = private_key.sign(
        message_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    signature_b64 = base64.b64encode(signature).decode('utf-8')

    return f"""{message_str}

=== SIGNATURE START ===
{signature_b64}
==== SIGNATURE END ====
siginfo: (RSA4096, PKCS1V15, SHA256, BASE64)
"""

def verify_signed_message(public_key, signed_text: str) -> bool:
    match = re.search(
        r'(?P<message>.*?)\n*=== SIGNATURE START ===\s*(?P<sig>.*?)\s*==== SIGNATURE END ====',
        signed_text,
        re.DOTALL
    )
    if not match:
        raise ValueError('signature block not found')

    message_str = match.group("message").rstrip()
    sig_str = ''.join(match.group("sig").split())
    signature_bytes = base64.b64decode(sig_str)

    # hash the message
    message_bytes = message_str.encode("utf-8")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message_bytes)
    message_hash = digest.finalize()

    try:
        public_key.verify(
            signature_bytes,
            message_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

#// main script start

if sys.argv[1] == '--generate':
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} --generate <key_name>")
        sys.exit(1)
    keyname = sys.argv[2]
    generate_keypair(keyname)

elif sys.argv[1] == "--sign":
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} --sign <message.txt> <private_key.pem>")
        sys.exit(1)
    
    msg_path = sys.argv[2]
    privkey_path = sys.argv[3]

    with open(msg_path, "r", encoding="utf-8") as f:
        message_str = f.read()

    with open(privkey_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    signed_message = sign_message(private_key, message_str)
    print(signed_message)

elif sys.argv[1] == "--verify":
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} --verify <signed_message.txt> <public_key.pem>")
        sys.exit(1)

    signed_path = sys.argv[2]
    pubkey_path = sys.argv[3]

    with open(pubkey_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(signed_path, "r", encoding="utf-8") as f:
        signed_text = f.read()

    isvalid = verify_signed_message(public_key, signed_text)

    if isvalid:
        print("signature's match")
    else:
        print("signature's do not match")

elif sys.argv[1] == "--help":
    print("""
usage: main.py <command> [options]

commands:
  --generate <key_name> // generate a 4096-bit rsa keypair with the given name
  --sign <message.txt> <private_key.pem> // sign a message file with a private key
  --verify <signed_message.txt> <public_key.pem> // verify a signed message with a public key
""")
    sys.exit(0)

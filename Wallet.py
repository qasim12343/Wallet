import hashlib
import ecdsa
import binascii
import base58


def create_pv(passphrase, seed_phrase):

    combined_seed = passphrase + seed_phrase
    hashed_seed = hashlib.sha256(combined_seed.encode()).hexdigest()
    pv = int(hashed_seed, 16)
    return pv


def pv_to_pkAdd(pv):

    signing_key = ecdsa.SigningKey.from_secret_exponent(
        pv, curve=ecdsa.SECP256k1)

    verifying_key = signing_key.verifying_key
    temp = bytes.fromhex("04")
    pk = temp + verifying_key.to_string()

    hashed_pk = hashlib.sha256(pk).digest()
    ripemd160_hash = hashlib.new("ripemd160")
    ripemd160_hash.update(hashed_pk)
    hashedRipe_pk = ripemd160_hash.digest()
    hashedRipe_pk = b"\x00" + hashedRipe_pk

    checksum = hashlib.sha256(hashlib.sha256(
        hashedRipe_pk).digest()).digest()[:4]

    hashedRipe_pk += checksum
    address = base58.b58encode(hashedRipe_pk)
    return pk, address


def main():

    passphrase = input()
    seed_phrase = input()

    pv = create_pv(passphrase, seed_phrase)
    pv_hex = hex(pv)
    pk, add = pv_to_pkAdd(pv)

    print(binascii.hexlify(pk).decode())
    print(add.decode())
    print(pv_hex)


if __name__ == "__main__":
    main()

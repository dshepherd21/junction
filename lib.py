from Crypto.Cipher import AES
import base64

MASTER_KEY="Some-long-base-key-to-use-as-encyrption-key"
#print AES.block_size
def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return base64.decodestring(data)
    
def encrypt_val(clear_text):
    enc_secret = AES.new(MASTER_KEY[:32])
    tag_string = (str(clear_text) +
                  (AES.block_size -
                   len(str(clear_text)) % AES.block_size) * "\0")
    cipher_text = base64.b64encode(enc_secret.encrypt(tag_string))

    return cipher_text
    
def decrypt_val(cipher_text):
    dec_secret = AES.new(MASTER_KEY[:32])
    #print cipher_text
    raw_decrypted = dec_secret.decrypt(base64.b64decode(cipher_text))
    #raw_decrypted=dec_secret.decrypt(decode_base64(cipher_text))
    clear_val = raw_decrypted.rstrip("\0")
    return clear_val


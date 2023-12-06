from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)

# 生成ECDSA密钥对
private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()

# 导出私钥到文件
with open("private_key.pem", "wb") as f:
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    f.write(private_key_pem)

# 导出公钥到文件
with open("public_key.pem", "wb") as f:
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f.write(public_key_pem)


# # 要签名的数据
# data = b"Hello, World!"
#
# # 生成签名
# signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

# # 验证签名
# try:
#     public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
#     print("Signature is valid.")
# except InvalidSignature:
#     print("Signature is invalid.")

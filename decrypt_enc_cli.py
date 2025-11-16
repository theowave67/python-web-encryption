#!/usr/bin/env python3
# decrypt_enc_cli.py
# 命令行解密原始 .enc 二进制加密文件（salt+nonce+ct）

import argparse
import json
import sys
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode())

def decrypt_file(enc_path: str, password: str) -> str | None:
    if not os.path.exists(enc_path):
        print(f"[ERROR] 文件不存在: {enc_path}", file=sys.stderr)
        return None

    try:
        with open(enc_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[ERROR] 读取文件失败: {e}", file=sys.stderr)
        return None

    if len(data) < 44:
        print("[ERROR] 文件太短（<44字节），可能已损坏", file=sys.stderr)
        return None

    salt = data[:16]
    nonce = data[16:28]
    ct_with_tag = data[28:]

    try:
        key = derive_key(password, salt)
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ct_with_tag, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"[ERROR] 解密失败（密码错误或文件损坏）: {e}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(
        description="命令行解密原始 .enc 二进制加密文件",
        epilog="示例: python decrypt_enc_cli.py data.json.enc mypass -o config.json"
    )
    parser.add_argument("enc_file", help="加密文件路径（如 data.json.enc）")
    parser.add_argument("password", help="解密密码")
    parser.add_argument("-o", "--output", help="输出明文 JSON 文件路径（默认打印到屏幕）")
    parser.add_argument("--raw", action="store_true", help="输出原始明文（不格式化 JSON）")

    args = parser.parse_args()

    result = decrypt_file(args.enc_file, args.password)
    if result is None:
        sys.exit(1)

    if args.output:
        try:
            if args.raw:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(result)
                print(f"[OK] 明文已保存到: {args.output}")
            else:
                config = json.loads(result)
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                print(f"[OK] 配置已保存到: {args.output}")
        except Exception as e:
            print(f"[ERROR] 保存文件失败: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if args.raw:
            print(result)
        else:
            try:
                config = json.loads(result)
                print(json.dumps(config, indent=2, ensure_ascii=False))
            except json.JSONDecodeError:
                print("[WARN] 不是有效 JSON，输出原始内容：")
                print(result)

if __name__ == "__main__":
    main()

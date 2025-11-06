# -*- coding: utf-8 -*-
import os
import re
import json
import time
import base64
import shutil
import requests
import platform
import subprocess
import threading
import argparse
import getpass
import logging
from threading import Thread

# ==================== FastAPI ====================
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

# ==================== 原有代码 ====================

DEBUG = os.environ.get("DDDEBUG", "false").lower() == "true"
PASSWD = os.environ.get("ENC_PASSWD", '')
ENC_PATH = os.environ.get("ENC_PATH", '')

# 配置 logging
logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG if DEBUG else logging.CRITICAL)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def write_log(*args, **kwargs):
    message = ' '.join(map(str, args))
    logger.debug(message)

write_log(f"current path: {os.getcwd()}")

# 加密相关（使用 cryptography 库）
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    write_log("请安装 cryptography: pip install cryptography")
    exit(1)

# 默认配置
DEFAULT_CONFIG = {
    'UPLOAD_URL': '',
    'PROJECT_URL': '',
    'AUTO_ACCESS': False,
    'FILE_PATH': './.cache',
    'SUB_PATH': 'silas0668',
    'UUID': '20e6e496-cf19-45c8-b883-14f5e11cd9f1',
    'NEZHA_SERVER': '',
    'NEZHA_PORT': '',
    'NEZHA_KEY': '',
    'ARGO_DOMAIN': '',
    'ARGO_AUTH': '',
    'ARGO_PORT': 8001,
    'CFIP': '194.53.53.7',
    'CFPORT': 443,
    'NAME': 'Modal',
    'CHAT_ID': '',
    'BOT_TOKEN': '',
    'SERVER_PORT': 8000,
    'PORT': 8000
}

PLAIN_FILE_DEFAULT = 'data.json'
ENCRYPTED_FILE_DEFAULT = 'data.json.enc'

# ==================== 加密/解密函数 ====================

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode())

def encrypt_data(plain_file: str, encrypted_file: str, password: str) -> bool:
    if not os.path.exists(plain_file):
        write_log(f"明文文件 {plain_file} 不存在！")
        return False

    with open(plain_file, 'r', encoding='utf-8') as f:
        data = f.read().encode('utf-8')

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, None)

    os.makedirs(os.path.dirname(encrypted_file), exist_ok=True) if os.path.dirname(encrypted_file) else None
    with open(encrypted_file, 'wb') as f:
        f.write(salt + nonce + ct)

    write_log(f"加密成功：{encrypted_file}")
    return True

def decrypt_data(encrypted_file: str, password: str) -> dict | None:
    if not os.path.exists(encrypted_file):
        write_log(f"密文文件 {encrypted_file} 不存在！")
        return None

    with open(encrypted_file, 'rb') as f:
        file_data = f.read()

    if len(file_data) < 44:
        write_log("密文文件损坏！")
        return None

    salt = file_data[:16]
    nonce = file_data[16:28]
    ciphertext_with_tag = file_data[28:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None).decode('utf-8')
        config = json.loads(plaintext)
        write_log(f"解密成功，从 {encrypted_file} 加载配置")
        return config
    except Exception as e:
        write_log(f"解密失败：密码错误或文件损坏！({e})")
        return None

# ==================== 加载配置 ====================

def load_config(encrypted_file: str, plain_file: str):
    config = DEFAULT_CONFIG.copy()

    if os.path.exists(encrypted_file):
        while True:
            if PASSWD:
                password = PASSWD
            else:
                password = getpass.getpass(f"请输入密文文件 [{encrypted_file}] 的解密密码：")
            file_config = decrypt_data(encrypted_file, password)
            if file_config:
                for key, value in file_config.items():
                    upper_key = key.upper()
                    if upper_key in config:
                        if isinstance(config[upper_key], bool):
                            config[upper_key] = bool(value)
                        elif isinstance(config[upper_key], int):
                            config[upper_key] = int(value)
                        else:
                            config[upper_key] = value
                return config
            write_log("密码错误，请重试！")

    if os.path.exists(plain_file):
        write_log(f"密文 [{encrypted_file}] 不存在，加载明文 [{plain_file}]")
        choice = input("是否加密明文到密文？(y/n)：").strip().lower()
        if choice == 'y':
            password = getpass.getpass("请输入加密密码：")
            password_confirm = getpass.getpass("确认密码：")
            if password != password_confirm:
                write_log("密码不匹配，使用明文配置")
            elif encrypt_data(plain_file, encrypted_file, password):
                choice_del = input("是否删除明文文件？(y/n)：").strip().lower()
                if choice_del == 'y':
                    os.remove(plain_file)
                    write_log("明文已删除")
                write_log("明文已加密，下次优先使用密文")
                return load_config(encrypted_file, plain_file)
        write_log("使用明文配置（不安全）")
        try:
            with open(plain_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
            write_log(f"配置从明文 [{plain_file}] 加载成功")
            for key, value in file_config.items():
                upper_key = key.upper()
                if upper_key in config:
                    if isinstance(config[upper_key], bool):
                        config[upper_key] = bool(value)
                    elif isinstance(config[upper_key], int):
                        config[upper_key] = int(value)
                    else:
                        config[upper_key] = value
            return config
        except Exception as e:
            write_log(f"加载明文失败: {e}")

    write_log("无配置文件，使用默认配置")
    return config

# ==================== 命令行参数 ====================

parser = argparse.ArgumentParser(description="")
parser.add_argument('--encrypt', action='store_true', help='仅加密明文到密文')
parser.add_argument('--run-http', action='store_true', default=False, help='是否运行 HTTP 服务器')
parser.add_argument('--plain', type=str, default=PLAIN_FILE_DEFAULT)
parser.add_argument('--encrypted', type=str, default=ENCRYPTED_FILE_DEFAULT)
args = parser.parse_args()
if not ENC_PATH:
    ENC_PATH = args.encrypted

if args.encrypt:
    password = PASSWD or getpass.getpass("请输入加密密码：")
    password_confirm = getpass.getpass("确认密码：") if not PASSWD else password
    if password != password_confirm:
        write_log("密码不匹配！")
        exit(1)
    if encrypt_data(args.plain, ENC_PATH, password):
        write_log(f"加密完成！密文保存到 [{ENC_PATH}]")
    exit(0)

# 正常运行：加载配置
config = load_config(ENC_PATH, args.plain)

# 从 config 获取变量
UPLOAD_URL = config['UPLOAD_URL']
PROJECT_URL = config['PROJECT_URL']
AUTO_ACCESS = config['AUTO_ACCESS']
FILE_PATH = config['FILE_PATH']
SUB_PATH = config['SUB_PATH']
UUID = config['UUID']
NEZHA_SERVER = config['NEZHA_SERVER']
NEZHA_PORT = config['NEZHA_PORT']
NEZHA_KEY = config['NEZHA_KEY']
ARGO_DOMAIN = config['ARGO_DOMAIN']
ARGO_AUTH = config['ARGO_AUTH']
ARGO_PORT = int(config['ARGO_PORT'])
CFIP = config['CFIP']
CFPORT = int(config['CFPORT'])
NAME = config['NAME']
CHAT_ID = config['CHAT_ID']
BOT_TOKEN = config['BOT_TOKEN']
PORT = int(config.get('SERVER_PORT') or config.get('PORT') or 8000)

# ==================== 全局路径 ====================

npm_path = os.path.join(FILE_PATH, 'npm')
php_path = os.path.join(FILE_PATH, 'php')
web_path = os.path.join(FILE_PATH, 'web')
bot_path = os.path.join(FILE_PATH, 'bot')
sub_path = os.path.join(FILE_PATH, 'sub.txt')
list_path = os.path.join(FILE_PATH, 'list.txt')
boot_log_path = os.path.join(FILE_PATH, 'boot.log')
config_path = os.path.join(FILE_PATH, 'config.json')

# ==================== 业务函数 ====================

def create_directory():
    if not os.path.exists(FILE_PATH):
        os.makedirs(FILE_PATH)
        write_log(f"{FILE_PATH} is created")
    else:
        write_log(f"{FILE_PATH} already exists")

def delete_nodes():
    try:
        if not UPLOAD_URL or not os.path.exists(sub_path):
            return
        with open(sub_path, 'r') as file:
            file_content = file.read()
        decoded = base64.b64decode(file_content).decode('utf-8')
        nodes = [line for line in decoded.split('\n') if any(protocol in line for protocol in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
        if nodes:
            requests.post(f"{UPLOAD_URL}/api/delete-nodes",
                          data=json.dumps({"nodes": nodes}),
                          headers={"Content-Type": "application/json"})
    except Exception as e:
        write_log(f"Error in delete_nodes: {e}")

def cleanup_old_files():
    paths_to_delete = ['web', 'bot', 'npm', 'php', 'boot.log', 'list.txt']
    for file in paths_to_delete:
        file_path = os.path.join(FILE_PATH, file)
        try:
            if os.path.exists(file_path):
                if os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                else:
                    os.remove(file_path)
        except Exception as e:
            write_log(f"Error removing {file_path}: {e}")

def get_system_architecture():
    architecture = platform.machine().lower()
    if 'arm' in architecture or 'aarch64' in architecture:
        return 'arm'
    else:
        return 'amd'

def download_file(file_name, file_url):
    file_path = os.path.join(FILE_PATH, file_name)
    try:
        response = requests.get(file_url, stream=True)
        response.raise_for_status()
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        write_log(f"Download {file_name} successfully")
        return True
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        write_log(f"Download {file_name} failed: {e}")
        return False

def get_files_for_architecture(architecture):
    if architecture == 'arm':
        base_files = [
            {"fileName": "web", "fileUrl": "https://arm64.ssss.nyc.mn/web"},
            {"fileName": "bot", "fileUrl": "https://arm64.ssss.nyc.mn/2go"}
        ]
    else:
        base_files = [
            {"fileName": "web", "fileUrl": "https://amd64.ssss.nyc.mn/web"},
            {"fileName": "bot", "fileUrl": "https://amd64.ssss.nyc.mn/2go"}
        ]

    if NEZHA_SERVER and NEZHA_KEY:
        if NEZHA_PORT:
            npm_url = "https://arm64.ssss.nyc.mn/agent" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/agent"
            base_files.insert(0, {"fileName": "npm", "fileUrl": npm_url})
        else:
            php_url = "https://arm64.ssss.nyc.mn/v1" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/v1"
            base_files.insert(0, {"fileName": "php", "fileUrl": php_url})
    return base_files

def authorize_files(file_paths):
    for relative_file_path in file_paths:
        absolute_file_path = os.path.join(FILE_PATH, relative_file_path)
        if os.path.exists(absolute_file_path):
            try:
                os.chmod(absolute_file_path, 0o775)
                write_log(f"Empowerment success for {absolute_file_path}: 775")
            except Exception as e:
                write_log(f"Empowerment failed for {absolute_file_path}: {e}")

def argo_type():
    if not ARGO_AUTH or not ARGO_DOMAIN:
        write_log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels")
        return

    if "TunnelSecret" in ARGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        tunnel_id = ARGO_AUTH.split('"')[11]
        tunnel_yml = f"""
tunnel: {tunnel_id}
credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
            f.write(tunnel_yml)
    else:
        write_log("Use token connect to tunnel,please set the {PORT} in cfd")

def exec_cmd(command):
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        return stdout + stderr
    except Exception as e:
        write_log(f"Error executing command: {e}")
        return str(e)

def download_files_and_run():
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)

    if not files_to_download:
        write_log("Can't find a file for the current architecture")
        return

    download_success = True
    for file_info in files_to_download:
        if not download_file(file_info["fileName"], file_info["fileUrl"]):
            download_success = False

    if not download_success:
        write_log("Error downloading files")
        return

    files_to_authorize = ['npm', 'web', 'bot'] if NEZHA_PORT else ['php', 'web', 'bot']
    authorize_files(files_to_authorize)

    port = NEZHA_SERVER.split(":")[-1] if ":" in NEZHA_SERVER else ""
    nezha_tls = "true" if port in ["443", "8443", "2096", "2087", "2083", "2053"] else "false"

    if NEZHA_SERVER and NEZHA_KEY:
        if not NEZHA_PORT:
            config_yaml = f"""
client_secret: {NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 4
server: {NEZHA_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: {nezha_tls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}"""
            with open(os.path.join(FILE_PATH, 'config.yaml'), 'w') as f:
                f.write(config_yaml)

    config_json = {
        "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
        "inbounds": [
            {"port": ARGO_PORT, "protocol": "vless", "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none", "fallbacks": [{"dest": 3001}, {"path": "/vless-argo", "dest": 3002}, {"path": "/vmess-argo", "dest": 3003}, {"path": "/trojan-argo", "dest": 3004}]}, "streamSettings": {"network": "tcp"}},
            {"port": 3001, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": "none"}, "streamSettings": {"network": "ws", "security": "none"}},
            {"port": 3002, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": [{"id": UUID, "level": 0}], "decryption": "none"}, "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/vless-argo"}}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
            {"port": 3003, "listen": "127.0.0.1", "protocol": "vmess", "settings": {"clients": [{"id": UUID, "alterId": 0}]}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-argo"}}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
            {"port": 3004, "listen": "127.0.0.1", "protocol": "trojan", "settings": {"clients": [{"password": UUID}]}, "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/trojan-argo"}}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}}
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]
    }
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config_json, f, ensure_ascii=False, indent=2)

    if NEZHA_SERVER and NEZHA_PORT and NEZHA_KEY:
        tls_flag = '--tls' if NEZHA_PORT in ['443', '8443', '2096', '2087', '2083', '2053'] else ''
        cmd = f"nohup {npm_path} -s {NEZHA_SERVER}:{NEZHA_PORT} -p {NEZHA_KEY} {tls_flag} >/dev/null 2>&1 &"
        exec_cmd(cmd)
        write_log('npm is running')
        time.sleep(1)
    elif NEZHA_SERVER and NEZHA_KEY:
        cmd = f"nohup {php_path} -c \"{os.path.join(FILE_PATH, 'config.yaml')}\" >/dev/null 2>&1 &"
        exec_cmd(cmd)
        write_log('php is running')
        time.sleep(1)
    else:
        write_log('NEZHA variable is empty, skipping running')

    cmd = f"nohup {web_path} -c {config_path} >/dev/null 2>&1 &"
    exec_cmd(cmd)
    write_log('web is running')
    time.sleep(1)

    if os.path.exists(bot_path):
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {ARGO_AUTH}"
        elif "TunnelSecret" in ARGO_AUTH:
            args = f"tunnel --edge-ip-version auto --config {os.path.join(FILE_PATH, 'tunnel.yml')} run"
        else:
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {boot_log_path} --loglevel info --url http://localhost:{ARGO_PORT}"
        exec_cmd(f"nohup {bot_path} {args} >/dev/null 2>&1 &")
        write_log('bot is running')
        time.sleep(2)

    time.sleep(5)
    extract_domains()

def extract_domains():
    argo_domain = None
    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain = ARGO_DOMAIN
        write_log(f'HOST: {argo_domain}')
        generate_links(argo_domain)
    else:
        try:
            with open(boot_log_path, 'r') as f:
                lines = f.read().split('\n')
            for line in lines:
                match = re.search(r'https?://([^ ]*trycloudflare\.com)', line)
                if match:
                    argo_domain = match.group(1)
                    write_log(f'ArgoDomain: {argo_domain}')
                    generate_links(argo_domain)
                    return
            write_log('ArgoDomain not found, re-running bot')
            if os.path.exists(boot_log_path):
                os.remove(boot_log_path)
            exec_cmd('pkill -f "[b]ot"')
            time.sleep(1)
            args = f'tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {boot_log_path} --loglevel info --url http://localhost:{ARGO_PORT}'
            exec_cmd(f'nohup {bot_path} {args} >/dev/null 2>&1 &')
            write_log('bot is running.')
            time.sleep(6)
            extract_domains()
        except Exception as e:
            write_log(f'Error reading boot.log: {e}')

def upload_nodes():
    if UPLOAD_URL and PROJECT_URL:
        sub_url = f"{PROJECT_URL}/{SUB_PATH}"
        try:
            requests.post(f"{UPLOAD_URL}/api/add-subscriptions", json={"subscription": [sub_url]}, headers={"Content-Type": "application/json"})
            write_log('Subscription uploaded successfully')
        except:
            pass
    elif UPLOAD_URL and os.path.exists(list_path):
        with open(list_path, 'r') as f:
            nodes = [line for line in f.read().split('\n') if any(p in line for p in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
        if nodes:
            try:
                requests.post(f"{UPLOAD_URL}/api/add-nodes", data=json.dumps({"nodes": nodes}), headers={"Content-Type": "application/json"})
                write_log('Nodes uploaded successfully')
            except:
                pass

def send_telegram():
    if not BOT_TOKEN or not CHAT_ID:
        return
    try:
        with open(sub_path, 'r') as f:
            message = f.read()
        escaped_name = re.sub(r'([_*\[\]()~>#+=|{}.!\-])', r'\\\1', NAME)
        requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", params={
            "chat_id": CHAT_ID,
            "text": f"**{escaped_name}节点推送通知**\n{message}",
            "parse_mode": "MarkdownV2"
        })
        write_log('Telegram message sent successfully')
    except Exception as e:
        write_log(f'Failed to send Telegram message: {e}')

def generate_links(argo_domain):
    meta = subprocess.run(['curl', '-s', 'https://speed.cloudflare.com/meta'], capture_output=True, text=True).stdout.split('"')
    ISP = f"{meta[25]}-{meta[17]}".replace(' ', '_').strip()
    time.sleep(2)
    VMESS = {"v": "2", "ps": f"{NAME}-{ISP}", "add": CFIP, "port": CFPORT, "id": UUID, "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": argo_domain, "path": "/vmess-argo?ed=2560", "tls": "tls", "sni": argo_domain, "alpn": "", "fp": "chrome"}
    list_txt = f"""
vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}

vmess://{base64.b64encode(json.dumps(VMESS).encode('utf-8')).decode('utf-8')}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}
    """.strip()
    with open(list_path, 'w', encoding='utf-8') as f:
        f.write(list_txt)
    sub_txt = base64.b64encode(list_txt.encode('utf-8')).decode('utf-8')
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(sub_txt)
    write_log(sub_txt)
    write_log(f"{sub_path} saved successfully")
    send_telegram()
    upload_nodes()
    return sub_txt

def add_visit_task():
    if not AUTO_ACCESS or not PROJECT_URL:
        write_log("Skipping adding automatic access task")
        return
    try:
        requests.post('https://keep.gvrander.eu.org/add-url', json={"url": PROJECT_URL}, headers={"Content-Type": "application/json"})
        write_log('automatic access task added successfully')
    except Exception as e:
        write_log(f'Failed to add URL: {e}')

def clean_files():
    def _cleanup():
        time.sleep(30)
        for p in [boot_log_path, config_path, list_path, web_path, bot_path, php_path, npm_path]:
            try:
                if os.path.exists(p):
                    shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
            except:
                pass
        print('App is running')
        print('Thank you for using this script, enjoy!')
    threading.Thread(target=_cleanup, daemon=True).start()

# ==================== FastAPI 应用 ====================

app = FastAPI()

@app.get("/")
async def root():
    return Response(content=b"Hello World", media_type="text/html")

@app.get(f"/{SUB_PATH}")
async def get_sub():
    if not os.path.exists(sub_path):
        raise HTTPException(status_code=404, detail="Not Found")
    with open(sub_path, "rb") as f:
        content = f.read()
    return Response(content=content, media_type="text/plain")

# ==================== 启动流程 ====================

def start_server():
    delete_nodes()
    cleanup_old_files()
    create_directory()
    argo_type()
    download_files_and_run()
    add_visit_task()
    clean_files()

# ==================== Modal 入口（返回 ASGI app）===================

def run_sync():
    Thread(target=start_server, daemon=True).start()
    return app

# ==================== 本地调试入口 ====================

if __name__ == "__main__":
    if args.run_http:
        import uvicorn
        print(f"本地调试：http://0.0.0.0:{PORT}")
        Thread(target=start_server, daemon=True).start()
        uvicorn.run(app, host="0.0.0.0", port=PORT)
    else:
        run_sync()
        print("业务逻辑已启动（无 HTTP）")
        while True:
            time.sleep(3600)
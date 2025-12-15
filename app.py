#!/usr/bin/env python3
# app2.py

import os
import sys
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
from typing import Union
from threading import Thread
from subprocess import Popen, PIPE

# ==================== FastAPI ====================
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials

# ==================== 加密库 ====================
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("请安装: pip install cryptography")
    sys.exit(1)

# ==================== 解密函数 ====================
def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode('utf-8'))

def decrypt_b64_source(b64_input: str, password: str):
    try:
        data = base64.b64decode(b64_input)
        if len(data) < 44:
            return None
        salt, nonce, ct = data[:16], data[16:28], data[28:]
        key = derive_key(password, salt)
        aes = AESGCM(key)
        plain = aes.decrypt(nonce, ct, None).decode('utf-8')
        return json.loads(plain)
    except:
        print("解密失败")
        return None

def load_config_from_file(file_path: str, password: str):
    if not os.path.exists(file_path):
        print(f"[ERROR] 文件不存在: {file_path}", file=sys.stderr)
        sys.exit(1)
    with open(file_path, 'r', encoding='utf-8') as f:
        b64_data = f.read().strip()
    return decrypt_b64_source(b64_data, password)

# ==================== 默认配置 ====================
DEFAULT_CONFIG = {
    'UPLOAD_URL': '',
    'PROJECT_URL': '',
    'AUTO_ACCESS': False,
    'FILE_PATH': './.cache',
    'SUB_PATH': 'silas0668',
    'UUID': '20e6e496-cf19-45c8-b883-14f5e11cd9f1',
    'ARGO_DOMAIN': '',
    'ARGO_AUTH': '',
    'ARGO_PORT': 8001,
    'CFIP': '194.53.53.7',
    'CFPORT': 443,
    'NAME': 'Modal',
    'CHAT_ID': '',
    'BOT_TOKEN': '',
    'SERVER_PORT': 3000,
    'WEB_HOST': '127.0.0.1',
    'AUTH_ACCESS': 'FF888.',
    'DEBUG': False,
    'RUN_HTTP': True
}

# ==================== 命令行参数 ====================
parser = argparse.ArgumentParser(description="运行服务（只解密配置）")
parser.add_argument('--input', help='指定 .sec 加密文件路径')
args = parser.parse_args()

# ==================== 加载配置 ====================
def load_config():
    PASSWD = os.environ.get("ENC_PASSWD", "")
    pwd = PASSWD or (getpass.getpass("请输入解密密码: ") if not PASSWD and sys.stdin.isatty() else PASSWD)

    config = None
    B64 = os.getenv('ENCRYPTED_B64', '').strip()
    if B64:
        print(f"使用环境变量配置: {B64}")
        config = decrypt_b64_source(B64, pwd)
        print(f"解密的配置信息: {config}")
    elif os.environ.get('ENC_DATA_FILE'):
        print("使用环境变量(ENC_DATA_FILE)配置")
        config = load_config_from_file(os.environ.get('ENC_DATA_FILE'), pwd)
    elif args.input:
        print("使用命令行指定配置文件")
        config = load_config_from_file(args.input, pwd)

    if not config:
        print('缺少配置信息')
        sys.exit(1)

    merged = DEFAULT_CONFIG.copy()
    for k, v in config.items():
        uk = k.upper()
        if uk in merged:
            if isinstance(merged[uk], bool):
                merged[uk] = bool(v)
            elif isinstance(merged[uk], int):
                merged[uk] = int(v)
            else:
                merged[uk] = v
    return merged

config = load_config()

# ==================== 全局变量 ====================
DEBUG       = config.get('DEBUG', False)
UPLOAD_URL  = config['UPLOAD_URL']
PROJECT_URL = config['PROJECT_URL']
AUTO_ACCESS = config['AUTO_ACCESS']
FILE_PATH   = config['FILE_PATH']
SUB_PATH    = config['SUB_PATH']
UUID        = config['UUID']
ARGO_DOMAIN = config['ARGO_DOMAIN']
ARGO_AUTH   = config['ARGO_AUTH']
ARGO_PORT   = int(config['ARGO_PORT'])
CFIP        = config['CFIP']
CFPORT      = int(config['CFPORT'])
NAME        = config['NAME']
CHAT_ID     = config['CHAT_ID']
BOT_TOKEN   = config['BOT_TOKEN']
WEB_HOST    = config.get('WEB_HOST', '127.0.0.1')
WEB_PORT    = int(config.get('SERVER_PORT'))
AUTH_ACCESS = config.get('AUTH_ACCESS', 'FF888.')
RUN_HTTP    = str(config.get('RUN_HTTP', 'true')).lower() == 'true'

# ==================== 路径 ====================
web_path      = os.path.join(FILE_PATH, 'web')
bot_path      = os.path.join(FILE_PATH, 'bot')
sub_path      = os.path.join(FILE_PATH, 'sub.txt')
list_path     = os.path.join(FILE_PATH, 'list.txt')
boot_log_path = os.path.join(FILE_PATH, 'boot.log')
config_path   = os.path.join(FILE_PATH, 'config.json')

# ==================== 日志工具 ====================
def log(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

# ==================== 进程管理 ====================
web_process: Union[Popen, None] = None
bot_process: Union[Popen, None] = None

def stop_processes():
    global web_process, bot_process
    for p in [web_process, bot_process]:
        if p and p.poll() is None:
            try:
                p.terminate()
                p.wait(timeout=5)
            except:
                p.kill()
    log("所有子进程已停止")

def tail_log(process: Popen, name: str):
    if not DEBUG or not process.stdout:
        return
    for line in iter(process.stdout.readline, ''):
        if not line:
            break
        log(f"[{name}] {line.rstrip()}")

# ==================== 业务函数 ====================
def create_directory():
    os.makedirs(FILE_PATH, exist_ok=True)
    log(f"目录 {FILE_PATH} 已创建")

def cleanup_old_files():
    for item in ['web', 'bot', 'boot.log', 'list.txt']:
        p = os.path.join(FILE_PATH, item)
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.remove(p)
        except:
            pass
    log("旧文件已清理")

def get_system_architecture():
    arch = platform.machine().lower()
    return 'arm' if 'arm' in arch or 'aarch64' in arch else 'amd'

def download_file(name: str, url: str):
    path = os.path.join(FILE_PATH, name)
    try:
        r = requests.get(url, stream=True, timeout=60)
        r.raise_for_status()
        with open(path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        log(f"下载 {name} 成功")
        return True
    except Exception as e:
        if os.path.exists(path):
            os.remove(path)
        log(f"下载 {name} 失败: {e}")
        return False

def authorize_files(files: list):
    for f in files:
        p = os.path.join(FILE_PATH, f)
        if os.path.exists(p):
            try:
                os.chmod(p, 0o775)
                log(f"{p} 已授权 775")
            except:
                pass

def argo_type():
    if not ARGO_AUTH or not ARGO_DOMAIN:
        log("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道")
        return
    if "TunnelSecret" in ARGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        tunnel_id = ARGO_AUTH.split('"')[11]
        yml = f"""
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
            f.write(yml)
        log("已生成固定域名 tunnel.yml")

def delete_nodes():
    try:
        if not UPLOAD_URL or not os.path.exists(sub_path):
            return
        with open(sub_path, 'r') as f:
            content = base64.b64decode(f.read()).decode('utf-8')
        nodes = [l for l in content.split('\n') if any(p in l for p in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
        if nodes:
            requests.post(f"{UPLOAD_URL}/api/delete-nodes",
                          json={"nodes": nodes},
                          headers={"Content-Type": "application/json"},
                          timeout=10)
            log("旧节点已删除")
    except:
        pass

def download_files_and_run():
    global web_process, bot_process

    arch = get_system_architecture()
    files = [
        {"fileName": "web", "fileUrl": f"https://{ 'arm64' if arch=='arm' else 'amd64' }.ssss.nyc.mn/web"},
        {"fileName": "bot", "fileUrl": f"https://{ 'arm64' if arch=='arm' else 'amd64' }.ssss.nyc.mn/2go"},
    ]

    for f in files:
        if not download_file(f["fileName"], f["fileUrl"]):
            log("下载失败，终止启动")
            return

    authorize_files(['web', 'bot'])

    # 生成 config.json
    config_json = {
        "log": {
            "access": "/dev/null",
            "error": "/dev/null",
            "loglevel": "none"
        },
        "inbounds": [
            {
                "port": ARGO_PORT,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": UUID,
                            "flow": "xtls-rprx-vision"
                        }
                    ],
                    "decryption": "none",
                    "fallbacks": [
                        {"dest": 3001},
                        {"path": "/vless-argo", "dest": 3002},
                        {"path": "/vmess-argo", "dest": 3003},
                        {"path": "/trojan-argo", "dest": 3004}
                    ]
                },
                "streamSettings": {"network": "tcp"}
            },
            {
                "port": 3001,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": UUID}],
                    "decryption": "none"
                },
                "streamSettings": {"network": "ws", "security": "none"}
            },
            {
                "port": 3002,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": UUID, "level": 0}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": "/vless-argo"}
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            },
            {
                "port": 3003,
                "listen": "127.0.0.1",
                "protocol": "vmess",
                "settings": {
                    "clients": [{"id": UUID, "alterId": 0}]
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {"path": "/vmess-argo"}
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            },
            {
                "port": 3004,
                "listen": "127.0.0.1",
                "protocol": "trojan",
                "settings": {
                    "clients": [
                        {"password": UUID}
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": "/trojan-argo"}
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"}
        ]
    }
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config_json, f, ensure_ascii=False, indent=2)

    # 启动 web
    web_process = Popen(
        [web_path, "-c", config_path],
        stdout=PIPE if DEBUG else subprocess.DEVNULL,
        stderr=subprocess.STDOUT if DEBUG else subprocess.DEVNULL,
        bufsize=1,
        universal_newlines=True
    )
    Thread(target=tail_log, args=(web_process, "WEB"), daemon=True).start()
    log("web 已启动")

    time.sleep(2)

    # 启动 bot (cloudflared)
    if os.path.exists(bot_path):
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
            cmd = [bot_path, "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run", "--token", ARGO_AUTH]
        elif ARGO_AUTH and "TunnelSecret" in ARGO_AUTH:
            cmd = [bot_path, "tunnel", "--edge-ip-version", "auto", "--config", os.path.join(FILE_PATH, 'tunnel.yml'), "run"]
        else:
            cmd = [bot_path, "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
                   "--logfile", boot_log_path, "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"]

        bot_process = Popen(
            cmd,
            stdout=PIPE if DEBUG else subprocess.DEVNULL,
            stderr=subprocess.STDOUT if DEBUG else subprocess.DEVNULL,
            bufsize=1,
            universal_newlines=True
        )
        Thread(target=tail_log, args=(bot_process, "BOT"), daemon=True).start()
        log("bot 已启动")

    time.sleep(8 if not DEBUG else 3)
    extract_domains()

def extract_domains():
    global bot_process        # ← 修复：在函数开头声明 global

    argo_domain = None
    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain = ARGO_DOMAIN
        log(f'固定域名: {argo_domain}')
        generate_links(argo_domain)
        return

    try:
        with open(boot_log_path, 'r') as f:
            lines = f.read()
        match = re.search(r'https?://([^ ]*trycloudflare\.com)', lines)
        if match:
            argo_domain = match.group(1)
            log(f'ArgoDomain: {argo_domain}')
            generate_links(argo_domain)
            return
    except:
        pass

    log('未找到 ArgoDomain，重新启动 bot')
    if os.path.exists(boot_log_path):
        os.remove(boot_log_path)
    if bot_process and bot_process.poll() is None:
        bot_process.terminate()
    time.sleep(1)

    cmd = [bot_path, "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
           "--logfile", boot_log_path, "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"]
    bot_process = Popen(cmd,
                        stdout=PIPE if DEBUG else subprocess.DEVNULL,
                        stderr=subprocess.STDOUT if DEBUG else subprocess.DEVNULL,
                        bufsize=1,
                        universal_newlines=True)
    Thread(target=tail_log, args=(bot_process, "BOT"), daemon=True).start()
    time.sleep(10)
    extract_domains()

def generate_links(argo_domain: str):
    def get_isp_from_ip_api():
        try:
            url = 'http://ip-api.com/json/'
            resp = requests.get(url, timeout=10)
            print(f"ip-api meta: {resp.text}")
            meta = resp.json()
            country = meta.get('countryCode', None)
            ip = meta.get('query', None)
            ISP = f"{country}-{ip}"
        except Exception as err:
            print(f"Get ISP info error: {err}")
            ISP = None
        return ISP

    def get_isp_from_ipapi():
        try:
            url = "https://api.ipapi.is"
            resp = requests.get(url, timeout=10)
            print(f"ipapi meta: {resp.text}")
            meta = resp.json()
            ip = meta.get('ip', '')
            country = meta.get('location', {}).get('country_code', None)
            ISP = f"{country}-{ip}"
        except Exception as err:
            print(f"Get ISP info error: {err}")
            ISP = None
        return ISP
    
    ISP = get_isp_from_ip_api()
    if not ISP:
        ISP = get_isp_from_ipapi()
    if ISP is None:
        ISP = 'Unknown'
    ISP = ISP.replace(' ', '-')

    VMESS = {
        "v": "2", "ps": f"{NAME}-{ISP}", "add": CFIP, "port": CFPORT, "id": UUID, "aid": "0",
        "scy": "none", "net": "ws", "type": "none", "host": argo_domain,
        "path": "/vmess-argo?ed=2560", "tls": "tls", "sni": argo_domain, "alpn": "", "fp": "chrome"
    }

    list_txt = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}"""

    # vmess://{base64.b64encode(json.dumps(VMESS).encode()).decode()}

    # trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}
    #     """.strip()

    with open(list_path, 'w', encoding='utf-8') as f:
        f.write(list_txt)

    sub_txt = base64.b64encode(list_txt.encode()).decode()
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(sub_txt)

    log(f"订阅已生成: {sub_path}")
    send_telegram()
    upload_nodes()

def send_telegram():
    if not BOT_TOKEN or not CHAT_ID:
        return
    try:
        with open(sub_path, 'r') as f:
            message = f.read()
        escaped_name = re.sub(r'([_*\[\]()~>#+=|{}.!\-])', r'\\\1', NAME)
        requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", data={
            "chat_id": CHAT_ID,
            "text": f"**{escaped_name}节点推送通知**\n{message}",
            "parse_mode": "MarkdownV2"
        }, timeout=10)
        log("Telegram 已推送")
    except Exception as e:
        log(f"Telegram 发送失败: {e}")

def upload_nodes():
    if UPLOAD_URL and PROJECT_URL:
        sub_url = f"{PROJECT_URL}/{SUB_PATH}"
        try:
            requests.post(f"{UPLOAD_URL}/api/add-subscriptions",
                          json={"subscription": [sub_url]},
                          headers={"Content-Type": "application/json"}, timeout=10)
            log("订阅地址已上传")
        except:
            pass
    elif UPLOAD_URL and os.path.exists(list_path):
        with open(list_path, 'r') as f:
            nodes = [l.strip() for l in f if any(p in l for p in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
        if nodes:
            try:
                requests.post(f"{UPLOAD_URL}/api/add-nodes",
                              json={"nodes": nodes},
                              headers={"Content-Type": "application/json"}, timeout=10)
                log("节点已上传")
            except:
                pass

def add_visit_task():
    if not AUTO_ACCESS or not PROJECT_URL:
        log("跳过自动访问任务")
        return
    try:
        requests.post('https://keep.gvrander.eu.org/add-url',
                      json={"url": PROJECT_URL},
                      headers={"Content-Type": "application/json"},
                      timeout=10)
        log("自动访问任务添加成功")
    except Exception as e:
        log(f"添加访问任务失败: {e}")

def clean_files():
    def _cleanup():
        time.sleep(30)
        paths = [boot_log_path, config_path, list_path, web_path, bot_path]
        for p in paths:
            try:
                if os.path.exists(p):
                    if os.path.isdir(p):
                        shutil.rmtree(p)
                    else:
                        os.remove(p)
            except:
                pass
        log("临时文件已清理，感谢使用！")
    Thread(target=_cleanup, daemon=True).start()

# ==================== FastAPI ====================
def create_app():
    app = FastAPI()
    security = HTTPBasic()

    def verify_password(credentials: HTTPBasicCredentials = Depends(security)):
        if credentials.password != AUTH_ACCESS:
            raise HTTPException(status_code=401, detail="Invalid password")
        return True

    @app.get("/")
    async def root():
        return Response(content=b"Hello World", media_type="text/html")

    @app.get("/healthy_check")
    async def root():
        return Response(content=b"OK", media_type="text/html")

    @app.get(f"/{SUB_PATH}")
    async def get_sub(request: Request, _: bool = Depends(verify_password)):
        client_ip = request.client.host
        log(f"订阅被访问，IP: {client_ip}")
        if not os.path.exists(sub_path):
            raise HTTPException(status_code=404, detail="Not Found")
        with open(sub_path, "rb") as f:
            return Response(content=f.read(), media_type="text/plain")

    return app

# ==================== 启动入口 ====================
def start_server():
    delete_nodes()
    cleanup_old_files()
    create_directory()
    argo_type()
    download_files_and_run()
    add_visit_task()
    clean_files()

# ==================== 主程序 ====================
if __name__ == "__main__":
    print(f"配置加载成功")
    if RUN_HTTP:
        import uvicorn
        Thread(target=start_server, daemon=True).start()
        uvicorn.run(create_app(), host=WEB_HOST, port=WEB_PORT)
    else:
        start_server()
        print("所有服务已启动（非 HTTP 模式）")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("收到退出信号")
            stop_processes()
            sys.exit(0)

# serve_modal.py
from pathlib import Path
import os
import modal

# 从环境变量读取加密文件路径（默认 data.json.enc）
enc_local_path = Path(os.getenv("ENC_PATH", "data.json.enc"))

if not enc_local_path.exists():
    raise FileNotFoundError(f"加密配置文件未找到: {enc_local_path}")

web_script_local_path = Path(__file__).parent / "app.py"
web_script_remote_path = "/root/app.py"

image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("curl", "ca-certificates")
    .pip_install_from_requirements("requirements.txt")
    .add_local_file(enc_local_path, "/root/data.json.enc")
    .add_local_file(web_script_local_path, web_script_remote_path)
)

app = modal.App("web", image=image)

@app.function(
    min_containers=1,
    scaledown_window=60,
    buffer_containers=0,
    timeout=3600,
    cpu=1.0,
    memory=512,
)
@modal.concurrent(max_inputs=100)
@modal.asgi_app()
def run():
    from app import run_sync
    return run_sync()
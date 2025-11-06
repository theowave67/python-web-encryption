# Dockerfile
# ========= 多阶段构建：安装依赖 =========
FROM python:3.12-slim AS builder

WORKDIR /app

# 只复制 requirements.txt 先安装依赖（利用缓存）
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ========= 最终运行镜像 =========
FROM python:3.12-slim

WORKDIR /app

# 从 builder 阶段拷贝已安装的依赖
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

COPY app.py .
COPY requirements.txt .
COPY zeabur-data zeabur-data/

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start5s --retries=3 \
  CMD python -c "import requests; exit(0 if requests.get('http://localhost:8000').status_code == 200 else 1)" || exit 1

CMD ["python", "app.py", "--encrypted", "zeabur-data/silasvivid-outlook.data.enc", "--run-http"]

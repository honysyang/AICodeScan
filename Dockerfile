# Dockerfile 配置
FROM python:3.10-slim

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# 安装Python依赖
COPY requirements.txt .
RUN pip install -r requirements.txt

# 部署漏洞数据库
COPY cwe_patterns.json /app/database/

CMD ["python", "analyzer.py"]
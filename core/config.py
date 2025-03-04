# 安全分析配置

from pathlib import Path

class Config:
    BASE_DIR = Path(__file__).parent.parent
    REPORT_DIR = BASE_DIR / "reports"
    LOG_DIR = BASE_DIR / "logs"
    VULN_PATTERNS = BASE_DIR / "core/vulnerabilities/cwe_patterns.json"
    MITIGATIONS = BASE_DIR / "core/vulnerabilities/mitigations.json"

    # 配置文件
    OPENAI_API_KEY = "sk-GsMQf3GV3KR0QTO6OP6Acnezun1jUh92bt9JV13AvoGyNynM"
    OPENAI_BASE_URL = "https://api.chatanywhere.tech/v1"
    
    # 新增代码长度限制
    MAX_CODE_LENGTH = 6000  # 最大代码长度，单位：字符

    AI_MODEL = "gpt-4o-mini-ca"

    # 在__init__中自动创建目录
    def __init__(self):
        self.REPORT_DIR.mkdir(exist_ok=True)
        self.LOG_DIR.mkdir(exist_ok=True)

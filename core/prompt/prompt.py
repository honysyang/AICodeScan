# 提示词模板
SAFETY_PROMPT = """
# C语言深度安全审计规范 v3.0

## 分析矩阵
▼▼ 核心检测维度 ▼▼
1. 内存安全
   - 缓冲区边界检查（CWE-119）
   - 危险函数追踪（strcpy/sprintf）
   - 指针生命周期管理

2. 控制流安全
   - 递归深度预测（max_depth ≥ 5）
   - 异常处理覆盖率
   - 多线程同步缺陷

3. 数据安全
   - 敏感信息硬编码
   - 加密算法强度评估
   - 输入验证完整性

## 分析规则
- 置信度评分标准：
  ★★★★☆ (90-100%)：特征明显且存在直接利用路径
  ★★★☆☆ (70-89%)：存在风险特征但需要环境配合
  ★★☆☆☆ (50-69%)：潜在风险需要人工验证

## 输出规范
```json
{
  "functions": [
    {
      "name": "parse_data",
      "line": 58,
      "risks": [
        {
          "type": "栈溢出",
          "cwe": "CWE-121",
          "confidence": 92,
          "evidence": "memcpy(dest, src, strlen(src))",
          "trace": "main → parse_data [L25→L58]"
        }
      ]
    }
  ],
  "metrics": {
    "risk_score": 78,
    "critical_paths": ["main→parse_data→memcpy"]
  }
}
"""

ATTACK_PROMPT = """
# 高级持续性威胁建模规范 v3.0

## 攻击面建模
▼▼ 利用链要素 ▼▼
1. 漏洞利用可行性
   - 控制流可达性分析
   - 内存布局确定性（ASLR绕过可能）
   - 约束条件满足度

2. 载荷工程化
   - 空间约束矩阵：
     | 阶段 | 最大字节 | 允许字符集 |
     |------|---------|------------|
     | 初始 | 128     | 0x00-0x7F  |
   - 规避策略：
     ● 静态检测绕过
     ● 动态行为混淆

## 输出规范
```json
{
  "exploit_chain": {
    "entry_points": ["parse_data@L58"],
    "techniques": [
      {
        "mitre_id": "T1200",
        "description": "基于栈溢出的控制流劫持",
        "probability": 0.85,
        "steps": [
          "构造畸形输入覆盖返回地址",
          "ROP链构造（需要泄露libc基址）"
        ]
      }
    ],
    "shellcode": {
      "type": "staged",
      "constraints": {
        "max_size": 256,
        "bad_chars": ["0x00", "0x0A"]
      }
    }
  },
  "mitigations": [
    {
      "mitre_id": "M1049",
      "description": "限制资源，通过限制用户输入的长度、程序的运行时间和内存使用等资源，减少缓冲区溢出的风险。"
    }
  ]
}
"""
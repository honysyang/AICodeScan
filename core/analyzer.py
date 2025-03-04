import os
import sys
print("Current working directory:", os.getcwd())
print("Python path:", sys.path)
import re
import json
import argparse
from telnetlib import AYT
from openai import OpenAI
import plotly.express as px
import graphviz
from typing import Dict, List, Optional
from dataclasses import dataclass
from transformers import pipeline
from config import Config
import logging
from datetime import datetime
from prompt import SAFETY_PROMPT, ATTACK_PROMPT
from visualizer import CodeVisualizer


@dataclass
class CodeContext:
    file_path: str
    raw_content: str
    processed_content: str
    functions: List[Dict]

@dataclass
class AnalysisResult:
    safety_report: Dict
    attack_report: Dict

class CodeGuardian:
    def __init__(self, use_local_model: bool = False):
        self._init_logging()
        self.vuln_db = VulnerabilityDatabase()
        self.local_model = None
        if use_local_model:
            self._init_local_model()

    def analyze(self, file_path: str) -> AnalysisResult:
        """执行完整分析流程"""
        try:
            context = self._load_code(file_path)
            # 多引擎分析
            safety_data = self._safety_analysis(context)
            attack_data = self._attack_analysis(context, safety_data)
            
            return AnalysisResult(
                safety_report=safety_data,
                attack_report=attack_data
            )
        
        except Exception as e:
            self.logger.error(f"分析过程中发生错误: {str(e)}", exc_info=True)
            raise

    def _load_code(self, path: str) -> CodeContext:
        """加载并预处理代码"""
        self.logger.info(f"Loading code file: {path}")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw = f.read()
            self.logger.info(f"File loaded successfully. Size: {len(raw)} characters")
            processed = self._preprocess_code(raw)
            functions = self._extract_functions(processed)
            self.logger.debug(f"Preprocessed code lines: {len(processed.splitlines())}")
            self.logger.info(f"Extracted {len(functions)} functions")
            return CodeContext(
                file_path=path,
                raw_content=raw,
                processed_content=processed,
                functions=functions
            )
        except FileNotFoundError:
            self.logger.error(f"文件 {path} 未找到，请检查路径。")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load code: {str(e)}", exc_info=True)
            raise

    def _preprocess_code(self, code: str) -> str:
        """代码预处理"""
        # 移除单行注释
        code = re.sub(r'//.*', '', code)
        # 移除多行注释
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # 标准化空白字符
        return '\n'.join([line.strip() for line in code.split('\n') if line.strip()])

    def _extract_functions(self, code: str) -> List[Dict]:
        """提取函数定义"""
        functions = []
        pattern = r'(?P<return_type>\w+)\s+(?P<name>\w+)\s*\([^)]*\)\s*\{'
        for match in re.finditer(pattern, code):
            functions.append({
                'name': match.group('name'),
                'return_type': match.group('return_type'),
                'start_line': code[:match.start()].count('\n') + 1
            })
        return functions

    def _safety_analysis(self, context: CodeContext) -> Dict:
        """安全分析阶段"""
        # 本地漏洞检测
        local_findings = self.vuln_db.scan_code(context.processed_content)
        # AI分析
        ai_report = self._call_ai_engine(
            prompt=SAFETY_PROMPT,
            code=context.processed_content,
            context=local_findings
        )
        return self._merge_reports(local_findings, ai_report)

    def _attack_analysis(self, context: CodeContext, safety_data: Dict) -> Dict:
        """攻防分析阶段"""
        # AI分析
        ai_report = self._call_ai_engine(
            prompt=ATTACK_PROMPT,
            code=context.processed_content,
            context=safety_data
        )
        # 补充本地检测
        ai_report['mitigations'] = self.vuln_db.get_mitigations(
            ai_report.get('cwe_ids', [])
        )
        return ai_report

    def _call_ai_engine(self, prompt: str, code: str, context: Dict) -> Dict:
        """调用AI分析引擎"""
        self.logger.info("Initiating AI analysis...")
        self.logger.debug(f"Prompt: {prompt[:100]}...")
        self.logger.debug(f"Code snippet: {code[:200]}...")
        try:
            if self.local_model:
                self.logger.info("Using local model for analysis")
                return self._analyze_with_local_model(prompt, code, context)
            else:
                self.logger.info("Using OpenAI API for analysis")
                return self._analyze_with_openai(prompt, code, context)
        except Exception as e:
            self.logger.error(f"AI analysis failed: {str(e)}", exc_info=True)
            raise

    def _analyze_with_openai(self, prompt: str, code: str, context: Dict) -> Dict:
        """使用OpenAI分析"""
        try:
            client = OpenAI(
                api_key=Config.OPENAI_API_KEY,
                base_url=Config.OPENAI_BASE_URL
            )
            
            messages = self._build_messages(prompt, code, context)
            
            response = client.chat.completions.create(
                model=Config.AI_MODEL,
                messages=messages,
                temperature=0.2,
                max_tokens=1500,
                response_format={"type": "json_object"}
            )
            
            return self._process_ai_response(response)
            
        except Exception as e:
            self.logger.error(f"OpenAI API调用失败: {str(e)}", exc_info=True)
            raise RuntimeError(f"AI分析失败: {str(e)}")

    def _build_messages(self, prompt: str, code: str, context: Dict) -> List[Dict]:
        self.logger.debug(f"Using MAX_CODE_LENGTH: {Config.MAX_CODE_LENGTH}")
        return [
            {
                "role": "system",
                "content": f"{prompt}\n[重要提示]必须返回严格符合要求的JSON格式"
            },
            {
                "role": "user",
                "content": f"代码片段：\n{code[:Config.MAX_CODE_LENGTH]}\n\n上下文：{json.dumps(context)}"
            }
        ]

    def _process_ai_response(self, response) -> Dict:
        raw_content = response.choices[0].message.content
        cleaned_content = raw_content.replace('```json', '').replace('```', '').strip()
        
        try:
            return json.loads(cleaned_content)
        except json.JSONDecodeError:
            self.logger.error("JSON解析失败", extra={"raw_response": raw_content})
            raise

    def _init_local_model(self):
        """初始化本地模型"""
        try:
            self.local_model = pipeline(
                "text-generation",
                model="codellama/CodeLlama-13b-hf",
                device_map="auto"
            )
        except Exception as e:
            self.logger.error(f"本地模型初始化失败: {str(e)}", exc_info=True)
            self.local_model = None

    def _analyze_with_local_model(self, prompt: str, code: str, context: Dict) -> Dict:
        """使用本地模型分析"""
        input_text = f"{prompt}\n\n代码：\n{code[:3000]}\n\n上下文：{json.dumps(context)}"
        try:
            result = self.local_model(
                input_text,
                max_new_tokens=1000,
                temperature=0.1
            )
            return json.loads(result[0]['generated_text'])
        except json.JSONDecodeError as e:
            self.logger.error(f"本地模型解析失败: {str(e)}")
            return {"error": "本地模型解析失败"}
        except Exception as e:
            self.logger.error(f"本地模型分析失败: {str(e)}")
            return {"error": f"本地模型分析失败: {str(e)}"}

    def _init_logging(self):
        """初始化日志配置"""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, f"analysis_{timestamp}.log")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("CodeGuardian")
        self.logger.info("=" * 50)
        self.logger.info("Initializing CodeGuardian Analyzer")
        self.logger.info(f"Log file: {os.path.abspath(log_file)}")

    def _merge_reports(self, local_data: Dict, ai_data: Dict) -> Dict:
        """合并本地和AI分析结果"""
        self.logger.info("Merging local and AI analysis results")
        merged = {
            "functions": [],
            "risks": [],
            "metadata": {
                "local_findings": local_data.get('local_findings', []),
                "ai_findings": ai_data.get('risks', [])
            }
        }
        # 合并函数信息
        if 'functions' in ai_data:
            merged['functions'] = ai_data['functions']
        # 合并风险信息（去重）
        seen_cwe = set()
        for risk in local_data.get('local_findings', []) + ai_data.get('risks', []):
            if risk['cwe_id'] not in seen_cwe:
                # 确保每个风险项都有severity字段
                if 'severity' not in risk:
                    risk['severity'] = 5  # 默认中等风险
                merged['risks'].append(risk)
                seen_cwe.add(risk['cwe_id'])
        self.logger.debug(f"Merged report contains {len(merged['risks'])} unique risks")
        return merged



        
        

class VulnerabilityDatabase:
    """漏洞特征数据库"""
    def __init__(self):
        self.logger = logging.getLogger("VulnerabilityDB")
        self.logger.info("Loading vulnerability patterns...")
        try:
            with open('vulnerabilities/cwe_patterns.json', 'r', encoding='utf-8') as f:
                patterns = json.load(f)
                self._validate_patterns(patterns)
                self.patterns = patterns
                self.logger.info(f"Loaded {len(self.patterns)} CWE patterns")
            with open('vulnerabilities/mitigations.json', 'r', encoding='utf-8') as f:
                self.mitigations = json.load(f)
                self.logger.info(f"Loaded {len(self.mitigations)} mitigation methods")
        except FileNotFoundError:
            self.logger.error("漏洞特征数据库文件未找到，请检查路径。")
            raise
        except json.JSONDecodeError:
            self.logger.error("漏洞特征数据库文件格式错误，请检查JSON格式。")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load vulnerability database: {str(e)}")
            raise

    def _validate_patterns(self, patterns: Dict):
        """验证正则表达式模式"""
        for cwe_id, pattern in patterns.items():
            try:
                re.compile(pattern['regex'])
            except re.error as e:
                self.logger.error(f"Invalid regex pattern for {cwe_id}: {pattern['regex']}")
                raise ValueError(f"Invalid regex pattern for {cwe_id}: {str(e)}")

    def scan_code(self, code: str) -> Dict:
        """本地漏洞扫描"""
        findings = []
        for cwe_id, pattern in self.patterns.items():
            try:
                if re.search(pattern['regex'], code, re.MULTILINE):
                    findings.append({
                        'cwe_id': cwe_id,
                        'type': pattern['type'],
                        'description': pattern['description']
                    })
            except re.error as e:
                self.logger.error(f"正则表达式解析失败: {e} (CWE: {cwe_id}, 模式: {pattern['regex']})")
                continue
        return {'local_findings': findings}

    def get_mitigations(self, cwe_ids: List[str]) -> List[Dict]:
        """获取缓解措施"""
        return [self.mitigations.get(cwe_id) for cwe_id in cwe_ids]

class ReportGenerator:
    @staticmethod
    def save(report: AnalysisResult, format: str = 'all'):
        """生成规范化报告文件"""
        logger = logging.getLogger("ReportGen")
        try:
            os.makedirs("reports", exist_ok=True)
            logger.info("生成规范化报告...")
            
            # 安全报告（JSON美化格式）
            with open("reports/safety.json", 'w', encoding='utf-8') as f:
                json.dump(report.safety_report, f, 
                         indent=2, ensure_ascii=False,
                         sort_keys=True)
                logger.debug("生成安全报告：safety.json")
            
            # 攻击报告（JSON美化格式）
            with open("reports/attack.json", 'w', encoding='utf-8') as f:
                json.dump(report.attack_report, f,
                         indent=2, ensure_ascii=False,
                         sort_keys=True)
                logger.debug("生成攻击报告：attack.json")
            
            # Markdown综合报告
            with open("reports/summary.md", 'w', encoding='utf-8') as f:
                f.write("# 代码安全分析报告\n\n")
                f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # 风险摘要
                f.write("## 风险概览\n")
                f.write(f"共发现 {len(report.safety_report.get('risks', []))} 个潜在风险\n")
                f.write("### 高风险项TOP5\n")
                for idx, risk in enumerate(report.safety_report.get('risks', [])[:5], 1):
                    f.write(f"{idx}. **{risk['cwe_id']}** - {risk['description']}\n")
                
                # 攻击向量
                f.write("\n## 攻击向量分析\n")
                if report.attack_report.get('mitre_id',[]) and report.attack_report.get('technique',[]) and report.attack_report.get('probability',[]):
                    f.write("| MITRE ID | 技术名称 | 可能性 |\n")
                    f.write("|----------|----------|--------|\n")
                    f.write(f"| {report.attack_report.get('mitre_id')} | {report.attack_report.get('technique',[])} | {report.attack_report.get('probability',[])} |\n")
                else:
                    f.write("未发现可直接利用的攻击向量\n")
                
                # 修复建议
                f.write("\n## 修复建议\n")
                mitigations = report.attack_report.get('mitigations', [])
                if mitigations:
                    for mid, mit in enumerate(filter(None, mitigations), 1):
                        f.write(f"{mid}. {mit.get('description', '')}\n")
                        f.write(f"   - **实施步骤**: {mit.get('steps', '暂无')}\n")
                else:
                    f.write("暂无具体修复建议\n")
                
                logger.info("生成Markdown摘要：summary.md")
            
            logger.info(f"报告已保存至：{os.path.abspath('reports')}")
        except Exception as e:
            logger.error(f"报告生成失败: {str(e)}", exc_info=True)
            raise RuntimeError(f"报告保存失败: {str(e)}")


        
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CodeGuardian - 智能代码审计系统")
    parser.add_argument("file", help="目标C代码文件路径")
    parser.add_argument("--local", action="store_true",
                        help="使用本地模型分析")
    args = parser.parse_args()
    analyzer = CodeGuardian(use_local_model=args.local)
    try:
        result = analyzer.analyze(args.file)
        ReportGenerator.save(result)
        print("分析完成！结果保存在reports目录")
    except Exception as e:
        print(f"分析过程中发生错误: {str(e)}")
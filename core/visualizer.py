import plotly.express as px
import graphviz
from typing import Dict
import os

class CodeVisualizer:

    @staticmethod
    def generate_call_graph(report: Dict) -> str:
        """生成函数调用关系图"""
        try:
            dot = graphviz.Digraph()
            for func in report.get('functions', []):
                label = f"{func['name']}"
                if func.get('risk'):
                    label += f"\n!{func['risk']}"
                dot.node(func['name'], label)
                
            for edge in report.get('calls', []):
                dot.edge(edge['from'], edge['to'])
            
            os.makedirs("reports", exist_ok=True)
            dot.render('reports/call_graph.gv', format='png')
            return 'reports/call_graph.gv.png'
        except Exception as e:
            raise RuntimeError(f"Failed to generate call graph: {str(e)}")

    @staticmethod
    def generate_risk_map(report: Dict) -> str:
        """生成风险分布图"""
        try:
            import pandas as pd
            if not report.get('risks'):
                raise ValueError("No risks found in report")
                
            # 将数据转换为pandas DataFrame
            risks = report['risks']
            
            # 确保每个风险项都有severity字段
            for risk in risks:
                if 'severity' not in risk:
                    risk['severity'] = 5  # 默认中等风险
            
            df = pd.DataFrame(risks)
            
            fig = px.treemap(
                df,
                path=['cwe_id'],
                values='severity',
                title='风险分布图'
            )
            os.makedirs("reports", exist_ok=True)
            fig.write_html("reports/risk_distribution.html")
            return 'reports/risk_distribution.html'
        except ImportError as e:
            raise RuntimeError(f"缺少必要依赖: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"生成风险分布图失败: {str(e)}")

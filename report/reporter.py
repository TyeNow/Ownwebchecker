# -*- coding: utf-8 -*-
"""报告生成模块。"""

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from jinja2 import Template

from detectors.base import Finding
from lib.common import ScannerConfig

MD_TEMPLATE = """
# 授权网站安全扫描报告

- 生成时间：{{ now }}
- 扫描模式：低影响授权自查版
- 目标数量：{{ target_count }}
- 风险总数：{{ total_count }}

## 一、风险统计

| 风险等级 | 数量 |
|---|---:|
{% for risk, count in risk_counts.items() -%}
| {{ risk }} | {{ count }} |
{% endfor %}

## 二、漏洞详情

{% for target, findings in all_findings.items() %}
### 目标：{{ target }}

{% if not findings %}
未发现明显风险项。
{% endif %}

{% for f in findings %}
#### {{ loop.index }}. [{{ f.risk }}] {{ f.vuln_type }}

- URL：`{{ f.url }}`
- 参数：`{{ f.parameter }}`
- Payload/特征：`{{ f.payload }}`
- 证据：{{ f.evidence }}
- 修复建议：{{ f.recommendation }}

{% endfor %}
{% endfor %}

## 三、通用加固建议

1. 对所有用户输入实施白名单校验和上下文输出编码。
2. 数据库访问统一使用参数化查询。
3. 禁止向前端和错误页暴露堆栈、密钥、连接串。
4. 上传目录禁执行，文件名随机化，文件内容做魔数校验。
5. 服务端出站请求接入统一代理并限制私网、环回、云元数据地址。
6. 生产环境启用安全响应头：CSP、HSTS、X-Content-Type-Options、Referrer-Policy。
7. 对登录和敏感操作加入 MFA、CSRF Token、速率限制和审计日志。

## 四、法律与合规提醒

本报告仅用于授权安全测试和自有资产自查。未经授权扫描第三方系统可能违法。
"""

HTML_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>授权网站安全扫描报告</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.6;margin:2rem;}
table{border-collapse:collapse;width:100%;}
td,th{border:1px solid #ddd;padding:.5rem;}
.risk{font-weight:bold;}
code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px;}
</style>
</head>
<body>
<h1>授权网站安全扫描报告</h1>
<p>生成时间：{{ now }}；风险总数：{{ total_count }}</p>
<table>
<tr><th>目标</th><th>等级</th><th>类型</th><th>URL</th><th>参数</th><th>证据</th><th>建议</th></tr>
{% for target, findings in all_findings.items() %}
{% for f in findings %}
<tr>
<td>{{ target }}</td><td class="risk">{{ f.risk }}</td><td>{{ f.vuln_type }}</td>
<td><code>{{ f.url }}</code></td><td>{{ f.parameter }}</td><td>{{ f.evidence }}</td><td>{{ f.recommendation }}</td>
</tr>
{% endfor %}
{% endfor %}
</table>
</body>
</html>
"""


class Reporter:
    """报告生成器。"""

    def __init__(self, config: ScannerConfig) -> None:
        """初始化报告器。

        参数:
            config: 扫描配置。

        返回:
            None
        """
        self.config = config

    def flatten(self, all_findings: Dict[str, List[Finding]]) -> List[Finding]:
        """展开所有目标的发现。

        参数:
            all_findings: 目标到发现列表的映射。

        返回:
            List[Finding]: 展开后的列表。
        """
        result = []
        for items in all_findings.values():
            result.extend(items)
        return result

    def write_markdown(self, all_findings: Dict[str, List[Finding]], path: Path) -> None:
        """写入 Markdown 报告。

        参数:
            all_findings: 所有发现。
            path: 输出路径。

        返回:
            None
        """
        flat = self.flatten(all_findings)
        risk_counts = Counter(f.risk for f in flat)
        text = Template(MD_TEMPLATE).render(
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_count=len(all_findings),
            total_count=len(flat),
            risk_counts=dict(risk_counts),
            all_findings=all_findings
        )
        path.write_text(text, encoding="utf-8")

    def write_html(self, all_findings: Dict[str, List[Finding]], path: Path) -> None:
        """写入 HTML 报告。

        参数:
            all_findings: 所有发现。
            path: 输出路径。

        返回:
            None
        """
        flat = self.flatten(all_findings)
        text = Template(HTML_TEMPLATE).render(
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_count=len(flat),
            all_findings=all_findings
        )
        path.write_text(text, encoding="utf-8")

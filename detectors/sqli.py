# -*- coding: utf-8 -*-
"""SQL 注入低影响检测模块。"""

import re
from pathlib import Path
from typing import List
import aiohttp

from detectors.base import BaseDetector, Finding, TargetSurface
from lib.common import load_lines, replace_query_param

DEFAULT_PAYLOADS = [
    "'", "\"", "1'", "1\"", "' OR '1'='1", "\" OR \"1\"=\"1",
    "' AND '1'='2", "admin'--", "1) AND (1=1", "1) AND (1=2",
    "'))", "%27", "'/**/OR/**/'1'='1"
]

ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL",
    r"SQLite/JDBCDriver", r"Warning.*mssql_", r"ODBC SQL",
    r"Unclosed quotation mark", r"PDOException", r"MariaDB"
]


class SQLiDetector(BaseDetector):
    """SQL 注入检测器。"""

    name = "sqli"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """执行 SQL 注入低影响检测。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        payloads = load_lines(self.config.project_root / "payloads" / "sqli.txt", DEFAULT_PAYLOADS)[:80]
        timeout = aiohttp.ClientTimeout(total=20)

        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "Authorized-SafeScanner/2.0"}) as session:
            for s in surfaces:
                for param in s.params:
                    baseline_status, baseline_text, _, _ = await self.request_get(session, s.url)
                    for payload in payloads[:20]:
                        test_url = replace_query_param(s.url, param, payload)
                        status, text, _, _ = await self.request_get(session, test_url)
                        if status == 0:
                            continue
                        if any(re.search(p, text, re.I) for p in ERROR_PATTERNS):
                            findings.append(Finding(
                                url=s.url,
                                risk="高危",
                                vuln_type="SQL注入",
                                parameter=param,
                                payload=payload,
                                evidence="响应中出现数据库错误特征，可能存在错误型 SQL 注入。",
                                recommendation="使用参数化查询；关闭详细数据库错误；为数据库账号配置最小权限。"
                            ))
                            break
                        if baseline_text and abs(len(text) - len(baseline_text)) > max(500, len(baseline_text) * 0.35):
                            findings.append(Finding(
                                url=s.url,
                                risk="中危",
                                vuln_type="SQL注入疑似",
                                parameter=param,
                                payload=payload,
                                evidence="参数变异后响应长度显著变化，需要人工复核布尔型注入可能性。",
                                recommendation="检查该参数的 SQL 拼接逻辑，优先改为 Prepared Statement。"
                            ))
                            break
        return findings

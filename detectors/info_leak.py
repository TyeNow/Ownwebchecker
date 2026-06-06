# -*- coding: utf-8 -*-
"""信息泄露检测模块。"""

import re
from typing import List

from detectors.base import BaseDetector, Finding, TargetSurface

PATTERNS = {
    "phpinfo": r"PHP Version|phpinfo\(\)",
    "数据库连接信息": r"DB_PASSWORD|DB_USERNAME|mysql_connect|jdbc:mysql|postgres://",
    "云密钥": r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}",
    "API Key": r"api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}",
    "邮箱地址": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "堆栈信息": r"Traceback \(most recent call last\)|Stack trace|NullPointerException|at [a-zA-Z0-9_.]+\(",
    "调试模式": r"DEBUG\s*=\s*True|debug mode|development mode",
    "敏感注释": r"TODO|FIXME|test account|password",
    "源码泄露": r"<\?php|package main|def [a-zA-Z_]+\(",
    "版本泄露": r"Apache/[0-9.]+|nginx/[0-9.]+|PHP/[0-9.]+"
}


class InfoLeakDetector(BaseDetector):
    """信息泄露检测器。"""

    name = "info_leak"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """扫描页面样本中的敏感信息。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        for s in surfaces:
            text = s.body_sample or ""
            header_text = " ".join([f"{k}: {v}" for k, v in s.headers.items()])
            sample = text + "\n" + header_text
            for name, pattern in PATTERNS.items():
                m = re.search(pattern, sample, re.I)
                if m:
                    findings.append(Finding(
                        url=s.url,
                        risk="中危" if name not in ["邮箱地址", "版本泄露"] else "低危",
                        vuln_type=f"信息泄露-{name}",
                        parameter="-",
                        payload=pattern,
                        evidence=f"匹配到信息泄露特征：{m.group(0)[:120]}",
                        recommendation="移除敏感注释和调试输出；错误页统一处理；不要在前端暴露密钥或连接串。"
                    ))
        return findings

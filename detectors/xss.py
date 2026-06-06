# -*- coding: utf-8 -*-
"""XSS 低影响检测模块。"""

import html
from pathlib import Path
from typing import List
import aiohttp

from detectors.base import BaseDetector, Finding, TargetSurface
from lib.common import load_lines, replace_query_param

DEFAULT_PAYLOADS = [
    "<xss-safe-probe-001>",
    "\"><xss-safe-probe-002>",
    "'><xss-safe-probe-003>",
    "<svg data-safe-xss=1>",
    "<img alt=xss-safe-probe-004>",
    "&lt;xss-safe-probe-005&gt;",
    "%3Cxss-safe-probe-006%3E",
    "`xss-safe-probe-007`",
    "<a data-safe-xss=008>",
    "<div id=xss-safe-probe-009>",
    "{{xss-safe-probe-010}}"
]


class XSSDetector(BaseDetector):
    """XSS 检测器。"""

    name = "xss"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """执行反射型和 DOM 型 XSS 低影响检测。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        payloads = load_lines(self.config.project_root / "payloads" / "xss.txt", DEFAULT_PAYLOADS)[:40]
        timeout = aiohttp.ClientTimeout(total=20)

        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "Authorized-SafeScanner/2.0"}) as session:
            for s in surfaces:
                body = s.body_sample or ""
                if any(x in body for x in ["innerHTML", "document.write(", "location.hash", "eval("]):
                    findings.append(Finding(
                        url=s.url,
                        risk="低危",
                        vuln_type="DOM型XSS疑似",
                        parameter="-",
                        payload="-",
                        evidence="页面 JavaScript 包含 innerHTML/document.write/location.hash/eval 等高风险模式。",
                        recommendation="避免将未转义用户输入写入 DOM；使用 textContent、严格 CSP 和输出编码。"
                    ))

                for param in s.params:
                    for payload in payloads[:15]:
                        marker = "xss-safe-probe"
                        test_url = replace_query_param(s.url, param, payload)
                        status, text, _, _ = await self.request_get(session, test_url)
                        if status and marker in text and html.escape(marker) not in text:
                            findings.append(Finding(
                                url=s.url,
                                risk="中危",
                                vuln_type="反射型XSS疑似",
                                parameter=param,
                                payload=payload,
                                evidence="低影响探针在响应中被原样反射，需人工确认上下文是否可执行脚本。",
                                recommendation="对 HTML、属性、JavaScript、URL 不同上下文分别做输出编码；配置 CSP。"
                            ))
                            break
        return findings

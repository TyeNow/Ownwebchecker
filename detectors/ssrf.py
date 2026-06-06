# -*- coding: utf-8 -*-
"""SSRF 低影响检测模块。"""

from typing import List
import aiohttp

from detectors.base import BaseDetector, Finding, TargetSurface
from lib.common import replace_query_param

DEFAULT_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://169.254.169.254/",
    "http://metadata.google.internal/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_PING",
    "dict://127.0.0.1:11211/",
    "http://example.invalid/safe-ssrf-probe"
]


class SSRFDetector(BaseDetector):
    """SSRF 风险检测器。"""

    name = "ssrf"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """执行 SSRF 低影响检测。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        keys = ["url", "uri", "link", "target", "callback", "redirect", "next", "image", "api", "host"]
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "Authorized-SafeScanner/2.0"}) as session:
            for s in surfaces:
                for param in s.params:
                    if not any(k in param.lower() for k in keys):
                        continue
                    for payload in DEFAULT_PAYLOADS:
                        test_url = replace_query_param(s.url, param, payload)
                        status, text, headers, _ = await self.request_get(session, test_url)
                        sample = (text[:1000] + str(headers)).lower()
                        if any(x in sample for x in ["ec2", "metadata", "root:x:0:0", "connection refused", "redis_version"]):
                            findings.append(Finding(
                                url=s.url,
                                risk="高危",
                                vuln_type="SSRF疑似",
                                parameter=param,
                                payload=payload,
                                evidence="URL 型参数返回内网/元数据/本地资源相关特征。",
                                recommendation="对可请求 URL 做协议、域名、IP 段白名单；禁止访问内网和云元数据地址。"
                            ))
                            break
                    else:
                        findings.append(Finding(
                            url=s.url,
                            risk="低危",
                            vuln_type="SSRF入口提示",
                            parameter=param,
                            payload="-",
                            evidence="发现疑似 URL/回调类参数，需要确认服务端是否会主动请求该地址。",
                            recommendation="为服务端出站请求建立统一代理和 allowlist，阻断私网地址。"
                        ))
        return findings

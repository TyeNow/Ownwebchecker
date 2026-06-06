# -*- coding: utf-8 -*-
"""XXE 配置风险检测模块。"""

from typing import List
import aiohttp

from detectors.base import BaseDetector, Finding, TargetSurface

DEFAULT_PAYLOADS = [
    "<?xml version='1.0'?><root>safe</root>",
    "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY e 'safe'>]><root>&e;</root>",
    "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><root>&e;</root>",
    "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY e SYSTEM 'http://example.invalid/xxe'>]><root>&e;</root>",
    "<root><item>safeprobe</item></root>",
    "<?xml version='1.0' encoding='UTF-8'?><root/>",
    "<!DOCTYPE root><root>safe</root>",
    "<?xml version='1.0'?><root><![CDATA[safe]]></root>",
    "<?xml version='1.0'?><root>&lt;safe&gt;</root>",
    "<?xml version='1.0'?><root attr='safe'/>"
]


class XXEDetector(BaseDetector):
    """XXE 风险检测器。"""

    name = "xxe"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """检测 XML 入口的外部实体风险。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "Authorized-SafeScanner/2.0"}) as session:
            for s in surfaces:
                looks_xml = "xml" in (s.headers.get("content-type", "") + s.body_sample[:300]).lower()
                if looks_xml:
                    findings.append(Finding(
                        url=s.url,
                        risk="低危",
                        vuln_type="XXE配置待核查",
                        parameter="-",
                        payload=DEFAULT_PAYLOADS[1],
                        evidence="发现 XML 相关接口/响应。低影响版不强制改写业务请求体。",
                        recommendation="禁用外部实体和 DTD；使用安全 XML 解析器；限制 XML 文档大小。"
                    ))
        return findings

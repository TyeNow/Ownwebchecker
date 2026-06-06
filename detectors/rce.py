# -*- coding: utf-8 -*-
"""命令/代码执行风险低影响检测模块。"""

from typing import List
import aiohttp

from detectors.base import BaseDetector, Finding, TargetSurface
from lib.common import replace_query_param

DEFAULT_PAYLOADS = [
    "safeprobe", "safeprobe;", "safeprobe|", "safeprobe&&", "safeprobe`",
    "$(safeprobe)", "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
    "{{config}}", "__SAFE_PROBE__"
]


class RCEDetector(BaseDetector):
    """命令/模板/代码执行风险检测器。"""

    name = "rce"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """执行低影响 RCE 风险检测，不执行系统命令。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "Authorized-SafeScanner/2.0"}) as session:
            for s in surfaces:
                for param in s.params:
                    for payload in DEFAULT_PAYLOADS:
                        test_url = replace_query_param(s.url, param, payload)
                        status, text, _, _ = await self.request_get(session, test_url)
                        if status and ("49" in text and payload in ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]):
                            findings.append(Finding(
                                url=s.url,
                                risk="高危",
                                vuln_type="模板注入/RCE疑似",
                                parameter=param,
                                payload=payload,
                                evidence="算术模板探针疑似被服务端求值，存在模板注入风险。",
                                recommendation="禁止拼接模板表达式；使用沙箱模板引擎；隔离模板上下文。"
                            ))
                            break
                        if any(x in text.lower() for x in ["traceback", "stack trace", "syntaxerror", "parse error"]):
                            findings.append(Finding(
                                url=s.url,
                                risk="中危",
                                vuln_type="代码执行入口疑似",
                                parameter=param,
                                payload=payload,
                                evidence="特殊字符触发服务端异常堆栈，需复核是否存在代码/命令拼接。",
                                recommendation="不要将用户输入传入 eval、exec、system、Runtime.exec；统一白名单校验。"
                            ))
                            break
        return findings

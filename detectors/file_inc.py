# -*- coding: utf-8 -*-
"""文件包含/路径穿越低影响检测模块。"""

from typing import List
import aiohttp

from detectors.base import BaseDetector, Finding, TargetSurface
from lib.common import replace_query_param

DEFAULT_PAYLOADS = [
    "../safeprobe.txt", "../../safeprobe.txt", "../../../safeprobe.txt",
    "..%2fsafeprobe.txt", "%2e%2e%2fsafeprobe.txt", "....//safeprobe.txt",
    "/etc/passwd", "C:\\Windows\\win.ini", "php://filter/read=convert.base64-encode/resource=index.php",
    "file:///etc/passwd"
]


class FileIncludeDetector(BaseDetector):
    """文件包含与路径穿越检测器。"""

    name = "file_inc"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """执行文件包含检测。

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
                        low = text.lower()
                        if "root:x:0:0" in low or "[extensions]" in low or "pd9wah" in low:
                            findings.append(Finding(
                                url=s.url,
                                risk="高危",
                                vuln_type="文件包含/路径穿越",
                                parameter=param,
                                payload=payload,
                                evidence="响应包含系统文件或源码编码特征。",
                                recommendation="使用路径白名单；禁止用户控制文件路径；规范化路径后限制在安全目录。"
                            ))
                            break
        return findings

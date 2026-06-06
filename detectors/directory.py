# -*- coding: utf-8 -*-
"""目录扫描与敏感文件检测模块。"""

from typing import List
from urllib.parse import urljoin
import aiohttp

from detectors.base import BaseDetector, Finding, TargetSurface
from lib.common import load_lines

DEFAULT_DIRS = [
    "/admin", "/manager", "/dashboard", "/login", "/backend", "/console", "/actuator",
    "/robots.txt", "/sitemap.xml", "/.git/config", "/.svn/entries", "/wp-config.php.bak",
    "/config.php.bak", "/.env", "/backup.zip", "/www.zip", "/web.tar.gz", "/access.log",
    "/error.log", "/phpinfo.php", "/server-status", "/swagger-ui.html", "/api-docs"
]


class DirectoryDetector(BaseDetector):
    """敏感路径检测器。"""

    name = "directory"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """执行敏感路径探测。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        paths = load_lines(self.config.project_root / "payloads" / "dirs.txt", DEFAULT_DIRS)[:500]
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "Authorized-SafeScanner/2.0"}) as session:
            for path in paths:
                url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
                status, text, _, _ = await self.request_get(session, url)
                if status in [200, 401, 403]:
                    risk = "高危" if any(x in path for x in [".git", ".env", ".bak", ".zip", ".tar", "log"]) else "低危"
                    evidence = f"敏感路径返回状态码 {status}"
                    if "DB_PASSWORD" in text or "[core]" in text or "root:" in text:
                        risk = "高危"
                        evidence += "，且包含敏感关键字。"
                    findings.append(Finding(
                        url=url,
                        risk=risk,
                        vuln_type="敏感路径/文件",
                        parameter="-",
                        payload=path,
                        evidence=evidence,
                        recommendation="删除敏感备份和配置文件；限制后台路径访问；关闭目录索引。"
                    ))
        return findings

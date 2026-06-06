# -*- coding: utf-8 -*-
"""检测器基类和数据结构。"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List

import aiohttp

from lib.common import ScannerConfig


@dataclass
class TargetSurface:
    """爬虫发现的目标攻击面。"""
    url: str
    method: str
    params: List[str]
    forms: List[Dict]
    headers: Dict[str, str]
    body_sample: str
    status: int


@dataclass
class Finding:
    """漏洞或风险发现。"""
    url: str
    risk: str
    vuln_type: str
    parameter: str
    payload: str
    evidence: str
    recommendation: str


class BaseDetector:
    """所有检测模块的基类。"""

    name = "base"

    def __init__(self, config: ScannerConfig, logger: logging.Logger) -> None:
        """初始化检测器。

        参数:
            config: 扫描配置。
            logger: 日志对象。

        返回:
            None
        """
        self.config = config
        self.logger = logger

    async def request_get(self, session: aiohttp.ClientSession, url: str) -> tuple:
        """发送 GET 请求。

        参数:
            session: aiohttp 会话。
            url: 请求 URL。

        返回:
            tuple: 状态码、文本、响应头、耗时。
        """
        import time
        from lib.common import jitter_delay
        await jitter_delay(self.config.delay)
        start = time.perf_counter()
        try:
            async with session.get(url, proxy=self.config.proxy, allow_redirects=True) as resp:
                text = await resp.text(errors="ignore")
                return resp.status, text, dict(resp.headers), time.perf_counter() - start
        except Exception as exc:
            self.logger.debug("GET 请求失败：%s - %s", url, exc)
            return 0, "", {}, time.perf_counter() - start

    async def request_post(self, session: aiohttp.ClientSession, url: str, data: dict, headers: dict = None) -> tuple:
        """发送 POST 请求。

        参数:
            session: aiohttp 会话。
            url: 请求 URL。
            data: 表单数据。
            headers: 请求头。

        返回:
            tuple: 状态码、文本、响应头、耗时。
        """
        import time
        from lib.common import jitter_delay
        await jitter_delay(self.config.delay)
        start = time.perf_counter()
        try:
            async with session.post(url, data=data, headers=headers or {}, proxy=self.config.proxy, allow_redirects=True) as resp:
                text = await resp.text(errors="ignore")
                return resp.status, text, dict(resp.headers), time.perf_counter() - start
        except Exception as exc:
            self.logger.debug("POST 请求失败：%s - %s", url, exc)
            return 0, "", {}, time.perf_counter() - start

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """执行检测。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 检测结果。
        """
        raise NotImplementedError

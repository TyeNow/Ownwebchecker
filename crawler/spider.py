# -*- coding: utf-8 -*-
"""异步智能爬虫。"""

import asyncio
import logging
from collections import deque
from typing import Deque, Dict, List, Set, Tuple

import aiohttp

from crawler.parser import extract_forms, extract_links, extract_url_params
from detectors.base import TargetSurface
from lib.common import ScannerConfig, jitter_delay, normalize_url, same_scope


class Spider:
    """异步爬虫类。"""

    def __init__(self, config: ScannerConfig, logger: logging.Logger) -> None:
        """初始化爬虫。

        参数:
            config: 扫描配置。
            logger: 日志对象。

        返回:
            None
        """
        self.config = config
        self.logger = logger

    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Tuple[int, str, Dict[str, str]]:
        """请求页面内容。

        参数:
            session: aiohttp 会话。
            url: 目标 URL。

        返回:
            Tuple[int, str, Dict[str, str]]: 状态码、文本、响应头。
        """
        await jitter_delay(self.config.delay)
        try:
            async with session.get(url, proxy=self.config.proxy, allow_redirects=True) as resp:
                ctype = resp.headers.get("content-type", "")
                if "text" not in ctype and "html" not in ctype and "json" not in ctype and "xml" not in ctype:
                    return resp.status, "", dict(resp.headers)
                text = await resp.text(errors="ignore")
                return resp.status, text, dict(resp.headers)
        except Exception as exc:
            self.logger.debug("爬取失败：%s - %s", url, exc)
            return 0, "", {}

    async def crawl(self, start_url: str) -> List[TargetSurface]:
        """广度优先爬取目标站点。

        参数:
            start_url: 起始 URL。

        返回:
            List[TargetSurface]: 攻击面列表。
        """
        start_url = normalize_url(start_url)
        queue: Deque[Tuple[str, int]] = deque([(start_url, 0)])
        visited: Set[str] = set()
        surfaces: List[TargetSurface] = []

        timeout = aiohttp.ClientTimeout(total=20)
        headers = {"User-Agent": "Authorized-SafeScanner/2.0"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            while queue:
                url, depth = queue.popleft()
                url = normalize_url(url)
                if url in visited or depth > self.config.depth:
                    continue
                if not same_scope(start_url, url):
                    continue

                visited.add(url)
                status, html, resp_headers = await self.fetch(session, url)
                if status == 0:
                    continue

                surface = TargetSurface(
                    url=url,
                    method="GET",
                    params=extract_url_params(url),
                    forms=extract_forms(url, html),
                    headers=resp_headers,
                    body_sample=html[:5000],
                    status=status
                )
                surfaces.append(surface)

                for link in extract_links(url, html):
                    n = normalize_url(link)
                    if n not in visited and same_scope(start_url, n):
                        queue.append((n, depth + 1))

        return surfaces

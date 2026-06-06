# -*- coding: utf-8 -*-
"""通用工具库。"""

import asyncio
import hashlib
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


@dataclass
class ScannerConfig:
    """扫描配置对象。"""
    concurrency: int
    depth: int
    delay: float
    proxy: Optional[str]
    modules: List[str]
    deep: bool
    ignore_robots: bool
    project_root: Path


def ensure_dirs() -> None:
    """确保运行所需目录存在。

    参数:
        无。

    返回:
        None
    """
    root = Path(__file__).resolve().parents[1]
    for name in ["data", "payloads", "report"]:
        (root / name).mkdir(exist_ok=True)


def normalize_url(url: str) -> str:
    """标准化 URL，去除片段并补充协议。

    参数:
        url: 原始 URL。

    返回:
        str: 标准化后的 URL。
    """
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", parsed.query, ""))


def same_scope(base_url: str, candidate_url: str) -> bool:
    """判断 URL 是否处于同主域或子域范围内。

    参数:
        base_url: 扫描根 URL。
        candidate_url: 候选 URL。

    返回:
        bool: 在范围内返回 True。
    """
    base_host = urlparse(base_url).hostname or ""
    cand_host = urlparse(candidate_url).hostname or ""
    return cand_host == base_host or cand_host.endswith("." + base_host)


def url_hash(url: str) -> str:
    """计算 URL 哈希值。

    参数:
        url: URL 字符串。

    返回:
        str: SHA256 哈希。
    """
    return hashlib.sha256(normalize_url(url).encode("utf-8")).hexdigest()


def replace_query_param(url: str, key: str, value: str) -> str:
    """替换 URL 查询参数值。

    参数:
        url: 原始 URL。
        key: 参数名。
        value: 新参数值。

    返回:
        str: 替换后的 URL。
    """
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    new_pairs = [(k, value if k == key else v) for k, v in pairs]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_pairs, doseq=True), p.fragment))


async def jitter_delay(base_delay: float) -> None:
    """执行随机延迟，降低对目标站点压力。

    参数:
        base_delay: 基础延迟秒数。

    返回:
        None
    """
    if base_delay <= 0:
        return
    await asyncio.sleep(random.uniform(base_delay * 0.5, base_delay * 1.5))


def load_lines(path: Path, defaults: List[str]) -> List[str]:
    """读取字典文件，失败时返回默认值。

    参数:
        path: 字典路径。
        defaults: 默认列表。

    返回:
        List[str]: 去重后的条目列表。
    """
    items = []
    if path.exists():
        items.extend([x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines()])
    items.extend(defaults)
    return list(dict.fromkeys([x for x in items if x and not x.startswith("#")]))

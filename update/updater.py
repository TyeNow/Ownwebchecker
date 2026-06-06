# -*- coding: utf-8 -*-
"""联网漏洞库和 Payload 更新模块。"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

import aiohttp

from lib.common import ScannerConfig

PAYLOAD_SOURCES: Dict[str, List[str]] = {
    "sqli": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_SQLI.txt"
    ],
    "xss": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/XSSDetection.txt"
    ],
    "xxe": [
        "https://raw.githubusercontent.com/payloadbox/xxe-injection-payload-list/master/Intruder/XXE-OOB.txt"
    ],
    "dirs": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    ],
    "passwords": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
    ]
}

CVE_SOURCES = [
    "https://cve.circl.lu/api/last",
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"
]


class VulnerabilityUpdater:
    """漏洞库更新器。"""

    def __init__(self, config: ScannerConfig, logger: logging.Logger) -> None:
        """初始化更新器。

        参数:
            config: 扫描配置。
            logger: 日志对象。

        返回:
            None
        """
        self.config = config
        self.logger = logger
        self.meta_path = config.project_root / "data" / "version.json"

    def need_update(self, force: bool) -> bool:
        """判断是否需要更新。

        参数:
            force: 是否强制更新。

        返回:
            bool: 需要更新返回 True。
        """
        if force or not self.meta_path.exists():
            return True
        try:
            meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
            last = datetime.fromisoformat(meta.get("updated_at"))
            return datetime.utcnow() - last > timedelta(days=1)
        except Exception:
            return True

    async def fetch_text(self, session: aiohttp.ClientSession, url: str) -> str:
        """下载文本内容。

        参数:
            session: aiohttp 会话。
            url: 下载地址。

        返回:
            str: 文本内容，失败返回空字符串。
        """
        try:
            async with session.get(url, proxy=self.config.proxy) as resp:
                if resp.status == 200:
                    return await resp.text(errors="ignore")
        except Exception as exc:
            self.logger.debug("下载失败：%s - %s", url, exc)
        return ""

    def merge_lines(self, existing_path: Path, new_texts: List[str], limit: int = 5000) -> int:
        """合并字典文本并去重。

        参数:
            existing_path: 本地文件路径。
            new_texts: 新下载文本列表。
            limit: 最大保留行数。

        返回:
            int: 写入条目数量。
        """
        items = []
        if existing_path.exists():
            items.extend(existing_path.read_text(encoding="utf-8", errors="ignore").splitlines())
        for text in new_texts:
            items.extend(text.splitlines())
        cleaned = []
        for x in items:
            x = x.strip()
            if not x or x.startswith("#") or len(x) > 300:
                continue
            cleaned.append(x)
        unique = list(dict.fromkeys(cleaned))[:limit]
        existing_path.write_text("\n".join(unique) + "\n", encoding="utf-8")
        return len(unique)

    async def update_payloads(self, session: aiohttp.ClientSession) -> Dict[str, int]:
        """更新 payload 字典。

        参数:
            session: aiohttp 会话。

        返回:
            Dict[str, int]: 每类字典条目数量。
        """
        counts = {}
        payload_dir = self.config.project_root / "payloads"
        payload_dir.mkdir(exist_ok=True)
        for name, urls in PAYLOAD_SOURCES.items():
            texts = [await self.fetch_text(session, url) for url in urls]
            count = self.merge_lines(payload_dir / f"{name}.txt", texts)
            counts[name] = count
        return counts

    async def update_cves(self, session: aiohttp.ClientSession) -> int:
        """更新 CVE 缓存，网络不可用时保留本地库。

        参数:
            session: aiohttp 会话。

        返回:
            int: 缓存 CVE 数量。
        """
        cve_path = self.config.project_root / "data" / "cves.json"
        all_items = []
        for url in CVE_SOURCES:
            text = await self.fetch_text(session, url)
            if not text:
                continue
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    all_items.extend(data)
                elif isinstance(data, dict):
                    if "vulnerabilities" in data:
                        all_items.extend(data["vulnerabilities"])
                    else:
                        all_items.append(data)
            except Exception:
                continue

        if all_items:
            cve_path.write_text(json.dumps(all_items, ensure_ascii=False, indent=2), encoding="utf-8")
        elif cve_path.exists():
            try:
                all_items = json.loads(cve_path.read_text(encoding="utf-8"))
            except Exception:
                all_items = []
        return len(all_items)

    async def update(self, force: bool = False) -> None:
        """执行漏洞库更新。

        参数:
            force: 是否强制更新。

        返回:
            None
        """
        if not self.need_update(force):
            self.logger.info("漏洞库未超过同步周期，使用本地缓存。")
            return

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "Authorized-SafeScanner-Updater/2.0"}) as session:
            payload_counts = await self.update_payloads(session)
            cve_count = await self.update_cves(session)

        meta = {
            "updated_at": datetime.utcnow().isoformat(),
            "payload_counts": payload_counts,
            "cve_count": cve_count,
            "version": "safe-db-" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
        }
        self.meta_path.parent.mkdir(exist_ok=True)
        previous = self.config.project_root / "data" / "version.previous.json"
        if self.meta_path.exists():
            previous.write_text(self.meta_path.read_text(encoding="utf-8"), encoding="utf-8")
        self.meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        self.logger.info("漏洞库更新完成：payload=%s, cve=%s", payload_counts, cve_count)

    def rollback(self) -> bool:
        """回滚到上一个漏洞库版本元信息。

        参数:
            无。

        返回:
            bool: 成功返回 True。
        """
        previous = self.config.project_root / "data" / "version.previous.json"
        if previous.exists():
            self.meta_path.write_text(previous.read_text(encoding="utf-8"), encoding="utf-8")
            return True
        return False

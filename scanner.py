#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
网站全漏洞扫描器 - 仅限授权安全测试使用

【法律声明】
1. 本工具仅可用于：
   - 您拥有完全所有权的系统
   - 已获得明确书面授权的系统
   - 合法授权的渗透测试项目
2. 未经授权使用本工具扫描他人系统属违法行为
3. 使用者须自行承担所有法律后果
4. 建议在本地测试环境（如 DVWA、Vulhub、OWASP Juice Shop）中验证功能

作者：Security Learning Edition
版本：2.0.0-safe
日期：2026-05-16

说明：
本版本为低影响授权自查版。它不会执行命令、上传 webshell、爆破账号或自动利用 CVE。
"""

import argparse
import asyncio
import logging
import sqlite3
from pathlib import Path
from typing import Dict, List, Type

from crawler.spider import Spider
from detectors.base import Finding, TargetSurface
from detectors.sqli import SQLiDetector
from detectors.xss import XSSDetector
from detectors.rce import RCEDetector
from detectors.file_inc import FileIncludeDetector
from detectors.upload import UploadDetector
from detectors.ssrf import SSRFDetector
from detectors.xxe import XXEDetector
from detectors.csrf import CSRFDetector
from detectors.directory import DirectoryDetector
from detectors.info_leak import InfoLeakDetector
from detectors.weak_pass import WeakPasswordDetector
from detectors.cve import CVEDetector
from lib.common import ScannerConfig, ensure_dirs, normalize_url
from report.reporter import Reporter
from update.updater import VulnerabilityUpdater


DETECTOR_MAP: Dict[str, Type] = {
    "sqli": SQLiDetector,
    "xss": XSSDetector,
    "rce": RCEDetector,
    "file_inc": FileIncludeDetector,
    "upload": UploadDetector,
    "ssrf": SSRFDetector,
    "xxe": XXEDetector,
    "csrf": CSRFDetector,
    "directory": DirectoryDetector,
    "info_leak": InfoLeakDetector,
    "weak_pass": WeakPasswordDetector,
    "cve": CVEDetector,
}


def build_logger(verbose: bool) -> logging.Logger:
    """创建日志对象。

    参数:
        verbose: 是否输出调试日志。

    返回:
        logging.Logger: 配置完成的日志对象。
    """
    logger = logging.getLogger("vuln_scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(console)
    return logger


def init_db(db_path: Path) -> sqlite3.Connection:
    """初始化 SQLite 数据库。

    参数:
        db_path: 数据库文件路径。

    返回:
        sqlite3.Connection: 数据库连接对象。
    """
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            url TEXT,
            risk TEXT,
            vuln_type TEXT,
            parameter TEXT,
            payload TEXT,
            evidence TEXT,
            recommendation TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def save_findings(conn: sqlite3.Connection, target: str, findings: List[Finding]) -> None:
    """保存检测结果到数据库。

    参数:
        conn: SQLite 连接。
        target: 目标地址。
        findings: 漏洞发现列表。

    返回:
        None
    """
    for f in findings:
        conn.execute(
            """INSERT INTO findings
            (target, url, risk, vuln_type, parameter, payload, evidence, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (target, f.url, f.risk, f.vuln_type, f.parameter, f.payload, f.evidence, f.recommendation)
        )
    conn.commit()


async def scan_target(target: str, config: ScannerConfig, logger: logging.Logger) -> List[Finding]:
    """扫描单个目标。

    参数:
        target: 目标 URL。
        config: 扫描配置。
        logger: 日志对象。

    返回:
        List[Finding]: 漏洞发现列表。
    """
    target = normalize_url(target)
    logger.info("开始扫描目标：%s", target)

    spider = Spider(config=config, logger=logger)
    surfaces: List[TargetSurface] = await spider.crawl(target)
    logger.info("[爬虫] 已发现 %s 个页面/接口，%s 个表单", len(surfaces), sum(len(s.forms) for s in surfaces))

    selected = config.modules or list(DETECTOR_MAP.keys())
    findings: List[Finding] = []

    for name in selected:
        cls = DETECTOR_MAP.get(name)
        if not cls:
            logger.warning("未知检测模块：%s", name)
            continue

        detector = cls(config=config, logger=logger)
        logger.info("启动检测模块：%s", name)
        try:
            results = await detector.run(target, surfaces)
            findings.extend(results)
            for f in results:
                logger.info("[%s] [%s] %s - %s", f.vuln_type, f.risk, f.url, f.evidence[:120])
        except Exception as exc:
            logger.exception("模块 %s 执行异常：%s", name, exc)

    logger.info("目标扫描完成：%s，发现 %s 个风险项", target, len(findings))
    return findings


def parse_args() -> argparse.Namespace:
    """解析命令行参数。

    参数:
        无。

    返回:
        argparse.Namespace: 参数对象。
    """
    parser = argparse.ArgumentParser(description="授权网站安全自查扫描器（低影响版）")
    parser.add_argument("-u", "--url", help="目标 URL")
    parser.add_argument("-f", "--file", help="目标文件，每行一个 URL")
    parser.add_argument("-t", "--threads", type=int, default=5, help="并发数，默认 5")
    parser.add_argument("-d", "--depth", type=int, default=3, help="爬虫深度，默认 3")
    parser.add_argument("-m", "--modules", help="检测模块，逗号分隔，例如 sqli,xss")
    parser.add_argument("--proxy", help="HTTP/HTTPS 代理，例如 http://127.0.0.1:8080")
    parser.add_argument("--delay", type=float, default=1.0, help="基础请求延迟秒数，默认 1")
    parser.add_argument("--deep", action="store_true", help="深度模式占位：可扩展 Playwright/Selenium")
    parser.add_argument("--update", action="store_true", help="强制更新漏洞库和 payload")
    parser.add_argument("--output", default="./report.md", help="报告输出路径")
    parser.add_argument("--html", action="store_true", help="同时生成 HTML 报告")
    parser.add_argument("--ignore-robots", action="store_true", help="忽略 robots.txt；仅在授权范围使用")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    return parser.parse_args()


async def main() -> None:
    """程序入口。

    参数:
        无。

    返回:
        None
    """
    args = parse_args()
    logger = build_logger(args.verbose)
    ensure_dirs()

    modules = [m.strip() for m in args.modules.split(",")] if args.modules else []
    config = ScannerConfig(
        concurrency=max(1, min(args.threads, 20)),
        depth=max(1, min(args.depth, 10)),
        delay=max(0, args.delay),
        proxy=args.proxy,
        modules=modules,
        deep=args.deep,
        ignore_robots=args.ignore_robots,
        project_root=Path(__file__).resolve().parent
    )

    updater = VulnerabilityUpdater(config=config, logger=logger)
    await updater.update(force=args.update)

    targets: List[str] = []
    if args.url:
        targets.append(args.url)
    if args.file:
        targets.extend([line.strip() for line in Path(args.file).read_text(encoding="utf-8").splitlines() if line.strip()])

    if not targets:
        raise SystemExit("请使用 -u 指定目标 URL，或使用 -f 指定目标文件。")

    conn = init_db(config.project_root / "data" / "scan_results.sqlite3")
    all_findings: Dict[str, List[Finding]] = {}

    semaphore = asyncio.Semaphore(config.concurrency)

    async def guarded_scan(t: str) -> None:
        """受并发控制的扫描任务。"""
        async with semaphore:
            findings = await scan_target(t, config, logger)
            all_findings[normalize_url(t)] = findings
            save_findings(conn, normalize_url(t), findings)

    await asyncio.gather(*(guarded_scan(t) for t in targets))

    reporter = Reporter(config=config)
    reporter.write_markdown(all_findings, Path(args.output))
    logger.info("Markdown 报告已生成：%s", args.output)

    if args.html:
        html_path = Path(args.output).with_suffix(".html")
        reporter.write_html(all_findings, html_path)
        logger.info("HTML 报告已生成：%s", html_path)


if __name__ == "__main__":
    asyncio.run(main())

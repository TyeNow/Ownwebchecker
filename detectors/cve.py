# -*- coding: utf-8 -*-
"""CVE 已知漏洞关联检测模块。"""

import json
import re
from pathlib import Path
from typing import List

from detectors.base import BaseDetector, Finding, TargetSurface


class CVEDetector(BaseDetector):
    """CVE 版本关联检测器。"""

    name = "cve"

    def load_cves(self) -> list:
        """加载本地 CVE 缓存。

        参数:
            无。

        返回:
            list: CVE 条目列表。
        """
        path = self.config.project_root / "data" / "cves.json"
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def fingerprint(self, s: TargetSurface) -> List[str]:
        """基于响应头和页面特征提取组件指纹。

        参数:
            s: 攻击面对象。

        返回:
            List[str]: 组件关键词列表。
        """
        text = " ".join([f"{k}: {v}" for k, v in s.headers.items()]) + " " + s.body_sample[:1000]
        fp = []
        for key in ["Apache", "nginx", "OpenResty", "PHP", "WordPress", "Joomla", "Drupal", "Spring", "Struts", "ThinkPHP", "Tomcat", "Jetty", "Express"]:
            if re.search(key, text, re.I):
                fp.append(key)
        return fp

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """执行 CVE 关联检测，不自动发送利用 PoC。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        cves = self.load_cves()
        for s in surfaces:
            fps = self.fingerprint(s)
            for fp in fps:
                matched = []
                for item in cves[:2000]:
                    title = json.dumps(item, ensure_ascii=False)
                    if fp.lower() in title.lower():
                        cve_id = item.get("id") or item.get("cve", {}).get("id") or "CVE-UNKNOWN"
                        matched.append(cve_id)
                    if len(matched) >= 3:
                        break
                findings.append(Finding(
                    url=s.url,
                    risk="低危",
                    vuln_type="CVE版本关联提示",
                    parameter=fp,
                    payload="-",
                    evidence=f"识别到组件 {fp}。本地漏洞库关联：{', '.join(matched) if matched else '暂无命中'}。",
                    recommendation="核实组件准确版本；优先升级到供应商支持版本；不要依赖自动 PoC 判断生产风险。"
                ))
        return findings

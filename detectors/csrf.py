# -*- coding: utf-8 -*-
"""CSRF 防护检查模块。"""

from typing import List

from detectors.base import BaseDetector, Finding, TargetSurface


class CSRFDetector(BaseDetector):
    """CSRF 检测器。"""

    name = "csrf"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """检查表单是否缺少 CSRF Token。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        token_keys = ["csrf", "_token", "authenticity_token", "nonce", "xsrf"]
        sensitive_words = ["password", "passwd", "email", "user", "admin", "transfer", "pay", "delete", "update"]
        for s in surfaces:
            for form in s.forms:
                method = form.get("method", "GET").upper()
                names = [i.get("name", "").lower() for i in form.get("inputs", [])]
                has_token = any(any(t in n for t in token_keys) for n in names)
                sensitive = any(any(w in n for w in sensitive_words) for n in names + [form.get("action", "").lower()])
                if method == "POST" and sensitive and not has_token:
                    findings.append(Finding(
                        url=form.get("action", s.url),
                        risk="中危",
                        vuln_type="CSRF防护缺失疑似",
                        parameter=",".join(names),
                        payload="-",
                        evidence="敏感 POST 表单未发现常见 CSRF Token 字段。",
                        recommendation="为状态变更请求加入不可预测 CSRF Token；校验 SameSite Cookie 和 Origin/Referer。"
                    ))
        return findings

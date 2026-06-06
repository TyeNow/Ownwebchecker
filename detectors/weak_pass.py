# -*- coding: utf-8 -*-
"""弱口令风险检查模块。"""

from typing import List

from detectors.base import BaseDetector, Finding, TargetSurface

COMMON_PASSWORDS = [
    "admin", "admin123", "password", "123456", "12345678",
    "qwerty", "root", "toor", "test", "guest",
    "welcome", "letmein"
]


class WeakPasswordDetector(BaseDetector):
    """弱口令风险提示模块。"""

    name = "weak_pass"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """识别登录表单并提示弱口令防护，不进行爆破。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        for s in surfaces:
            for form in s.forms:
                names = [i.get("name", "").lower() for i in form.get("inputs", [])]
                types = [i.get("type", "").lower() for i in form.get("inputs", [])]
                if "password" in types or any("pass" in n for n in names):
                    findings.append(Finding(
                        url=form.get("action", s.url),
                        risk="低危",
                        vuln_type="登录入口弱口令风险",
                        parameter=",".join(names),
                        payload=",".join(COMMON_PASSWORDS),
                        evidence="发现登录/密码表单。低影响版不执行密码猜测。",
                        recommendation="启用 MFA、登录限速、账号锁定、验证码和弱密码策略；监控异常登录。"
                    ))
        return findings

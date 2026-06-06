# -*- coding: utf-8 -*-
"""文件上传安全检查模块。"""

from typing import List

from detectors.base import BaseDetector, Finding, TargetSurface


class UploadDetector(BaseDetector):
    """文件上传风险检测器。"""

    name = "upload"

    async def run(self, target: str, surfaces: List[TargetSurface]) -> List[Finding]:
        """检查上传表单配置，不上传 webshell 或可执行脚本。

        参数:
            target: 根目标。
            surfaces: 攻击面列表。

        返回:
            List[Finding]: 发现列表。
        """
        findings: List[Finding] = []
        risky_exts = [".php", ".jsp", ".asp", ".aspx", ".phtml", ".shtml", ".exe", ".sh", ".py", ".js"]
        for s in surfaces:
            for form in s.forms:
                has_file = any(i.get("type", "").lower() == "file" for i in form.get("inputs", []))
                if has_file:
                    names = ",".join(i.get("name", "") for i in form.get("inputs", []))
                    findings.append(Finding(
                        url=form.get("action", s.url),
                        risk="中危",
                        vuln_type="文件上传配置风险",
                        parameter=names,
                        payload=",".join(risky_exts[:10]),
                        evidence="发现文件上传表单。低影响版仅提示风险，不上传测试脚本。",
                        recommendation="服务端校验 MIME、扩展名和文件魔数；重命名文件；上传目录禁执行；使用对象存储隔离。"
                    ))
        return findings

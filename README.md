# 网站授权安全自查扫描器（低影响版）

> 仅限扫描你拥有或获得书面授权的网站。本项目默认使用低影响检测策略，不执行命令、不上传 webshell、不爆破账号、不利用高危 CVE。

## 安装

```bash
pip install -r requirements.txt
```

## 使用

```bash
python scanner.py -u https://example.com
python scanner.py -u https://example.com -m sqli,xss,directory,info_leak
python scanner.py -f targets.txt -t 10 -d 3 --output report.md
python scanner.py -u https://example.com --update
```

## 输出

默认生成 Markdown 报告，包含：
- 扫描概览
- 漏洞/风险详情
- 攻击面清单
- 修复建议

## 安全边界

本实现是“学习与授权自查”版本：
- 不进行真实命令执行验证
- 不上传可执行脚本
- 不做弱口令爆破
- SSRF/XXE 使用非破坏性探测与配置检查
- CVE 模块只做版本关联和保守提示，不自动打 PoC

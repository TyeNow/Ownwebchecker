# -*- coding: utf-8 -*-
"""HTML 解析器。"""

from typing import Dict, List
from urllib.parse import urljoin, urlparse, parse_qsl
from bs4 import BeautifulSoup


def extract_links(base_url: str, html: str) -> List[str]:
    """从 HTML 中提取链接。

    参数:
        base_url: 当前页面 URL。
        html: HTML 内容。

    返回:
        List[str]: 绝对 URL 列表。
    """
    soup = BeautifulSoup(html or "", "lxml")
    links = []
    for tag in soup.find_all(["a", "link", "script"]):
        attr = "href" if tag.name in ["a", "link"] else "src"
        value = tag.get(attr)
        if value:
            links.append(urljoin(base_url, value))
    return links


def extract_forms(base_url: str, html: str) -> List[Dict]:
    """解析页面表单。

    参数:
        base_url: 当前页面 URL。
        html: HTML 内容。

    返回:
        List[Dict]: 表单结构列表。
    """
    soup = BeautifulSoup(html or "", "lxml")
    forms = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        action = urljoin(base_url, form.get("action") or base_url)
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inputs.append({
                "name": name,
                "type": inp.get("type") or inp.name,
                "value": inp.get("value") or ""
            })
        forms.append({"method": method, "action": action, "inputs": inputs})
    return forms


def extract_url_params(url: str) -> List[str]:
    """提取 URL GET 参数名。

    参数:
        url: 待解析 URL。

    返回:
        List[str]: 参数名列表。
    """
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def extract_comments(html: str) -> List[str]:
    """提取 HTML 注释。

    参数:
        html: HTML 内容。

    返回:
        List[str]: 注释列表。
    """
    soup = BeautifulSoup(html or "", "lxml")
    return [str(c) for c in soup.find_all(string=lambda text: isinstance(text, str) and "<!--" not in text)]

"""client.py —— phocinae-server HTTP 客户端。

httpx 重试（连接错误/5xx，指数退避，4xx 不重试）、超时分层
（connect 5s / 总 timeout 默认 30s）、错误分类（服务未启动给可行动提示）。
"""

import json
import os
import time

import httpx

from . import DEFAULT_MODEL, DEFAULT_SERVER, __version__

DEFAULT_TIMEOUT = 30.0
CONNECT_TIMEOUT = 5.0
DEFAULT_RETRIES = 3
MAX_QUESTIONS = 64
MAX_OPTIONS = 255
MAX_BATCH = 64

STARTUP_HINT = (
    "phocinae-server 似乎未在运行（{server}）。启动方式：\n"
    "  · 官方包：pip install phocinae-server，然后运行其 run_server.sh\n"
    "    （export PHOC_MODEL_DIR=<hf_repo 路径>；默认端口 8155）\n"
    "  · 源码：python -m phocinae.main --host 127.0.0.1 --port 8155\n"
    "或先运行 `phocinae ping` 确认服务状态；"
    "本 CLI 可用 --server 指定地址，或用环境变量 PHOC_SERVER。"
)


class PhocinaeError(Exception):
    """phocinae CLI 错误基类（exit 1）。"""


class ServerUnavailableError(PhocinaeError):
    """连接不上 / DNS / 连接拒绝。"""


class ServerTimeoutError(PhocinaeError):
    """请求超时。"""


class ServerHTTPError(PhocinaeError):
    """服务返回非 2xx（含 422 校验错、401 鉴权、413 超大）。"""

    def __init__(self, status, detail):
        super().__init__("phocinae-server 返回 HTTP %d：%s" % (status, detail))
        self.status = status
        self.detail = detail


class ResponseShapeError(PhocinaeError):
    """200 但响应结构不符合 /v1/systemone 协议。"""


# ---------------------------------------------------------- 应答解包（P0 兼容）
def _unwrap(value, keys):
    """兼容 P0 扁平值与旧 mock 嵌套对象（{type, noul|score|choice, ...}）。

    与 phocinae-mcp backend._unwrap 同口径。
    """
    seen = 0
    while isinstance(value, dict) and seen < 4:
        seen += 1
        hit = None
        for key in keys:
            if key in value:
                hit = value[key]
                break
        if hit is None:
            for key in ("answer", "value"):
                if key in value:
                    hit = value[key]
                    break
        if hit is None:
            return None
        value = hit
    return value


def unwrap_noul(value):
    return _unwrap(value, ("noul",))


def unwrap_choice(value):
    return _unwrap(value, ("choice", "index"))


def unwrap_score(value):
    return _unwrap(value, ("score",))


def noul_to_probability(noul):
    """扁平 bool → 放行概率；数值原样传递（与 guard/mcp 同口径）。"""
    if noul is True:
        return 1.0
    if noul is False:
        return 0.0
    return float(noul)


class Client:
    """/v1/systemone 客户端：重试 + 超时 + 错误分类。"""

    def __init__(self, server=DEFAULT_SERVER, timeout=DEFAULT_TIMEOUT,
                 retries=DEFAULT_RETRIES, model=DEFAULT_MODEL,
                 token=None, verbosity=0):
        self.server = (server or DEFAULT_SERVER).rstrip("/")
        self.timeout = max(0.1, float(timeout))
        self.retries = max(0, int(retries))
        self.model = model or DEFAULT_MODEL
        self.token = token or os.environ.get("PHOC_BEARER_TOKEN") or None
        self.verbosity = verbosity

    # ------------------------------------------------------------ 内部工具
    def _headers(self):
        h = {"Content-Type": "application/json",
             "User-Agent": "phocinae-cli/" + __version__}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        return h

    def _request(self, method, path, body=None):
        """带重试的 HTTP 请求。连接错误/超时/5xx 重试，4xx 立即抛出。"""
        url = self.server + path
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        last_exc = None
        for attempt in range(self.retries + 1):
            if self.verbosity >= 1 and attempt > 0:
                print("  [retry %d/%d] %s %s" % (attempt, self.retries, method, path),
                      file=os.sys.stderr)
            try:
                with httpx.Client(timeout=httpx.Timeout(
                        self.timeout, connect=CONNECT_TIMEOUT),
                        trust_env=False) as http:
                    resp = http.request(method, url, content=payload,
                                        headers=self._headers())
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_exc = exc
                if attempt < self.retries:
                    time.sleep(0.4 * (2 ** attempt))
                    continue
                raise ServerUnavailableError(
                    "无法连接 phocinae-server（%s）：%s\n%s"
                    % (url, exc, STARTUP_HINT.format(server=self.server))) from exc
            except httpx.ReadTimeout as exc:
                last_exc = exc
                if attempt < self.retries:
                    time.sleep(0.4 * (2 ** attempt))
                    continue
                raise ServerTimeoutError(
                    "请求超时（>%.1fs）：%s\n可加大 --timeout 或检查服务负载（"
                    "permute 端点 4× 前向、批量端点 ≤64 题，都更慢）。"
                    % (self.timeout, url)) from exc
            if 500 <= resp.status_code <= 599 and attempt < self.retries:
                last_exc = ServerHTTPError(resp.status_code,
                                           resp.text[:300].replace("\n", " "))
                time.sleep(0.4 * (2 ** attempt))
                continue
            if resp.status_code >= 400:
                if resp.status_code == 422:
                    detail = self._extract_detail(resp)
                    raise ServerHTTPError(422, detail)
                raise ServerHTTPError(resp.status_code,
                                      resp.text[:300].replace("\n", " "))
            return resp
        raise last_exc  # pragma: no cover

    @staticmethod
    def _extract_detail(resp):
        try:
            data = resp.json()
        except ValueError:
            return resp.text[:300].replace("\n", " ")
        if isinstance(data, dict):
            if "detail" in data:
                d = data["detail"]
                return json.dumps(d, ensure_ascii=False)[:300]
            err = data.get("error")
            if isinstance(err, dict):
                return "%s: %s" % (err.get("code"), err.get("message"))
        return resp.text[:300].replace("\n", " ")

    @staticmethod
    def _parse(resp):
        try:
            return resp.json()
        except ValueError as exc:
            raise ResponseShapeError(
                "服务响应不是合法 JSON（%s；URL=%s）" % (exc, resp.url)) from exc

    def _check_answers(self, body, questions):
        answers = body.get("answers")
        if not isinstance(answers, dict):
            raise ResponseShapeError(
                "响应缺少 answers 字段（可能是别的服务，"
                "请确认指向 phocinae-server 的 /v1/systemone）")
        missing = [q["id"] for q in questions if q["id"] not in answers]
        if missing:
            raise ResponseShapeError("响应缺少问题答案：%s" % missing)

    # ------------------------------------------------------------ 对外接口
    def systemone(self, state, questions, perm=False):
        """POST /v1/systemone（perm=True 时走 /permute）。"""
        body = {"model": self.model, "state": state, "questions": questions}
        path = "/v1/systemone/permute" if perm else "/v1/systemone"
        resp = self._request("POST", path, body)
        data = self._parse(resp)
        if not isinstance(data, dict):
            raise ResponseShapeError("响应顶层不是 JSON 对象")
        self._check_answers(data, questions)
        return data

    def batch(self, items, perm=False):
        """POST /v1/systemone/batch；items = [(state, questions), ...]。
        自动按 MAX_BATCH=64 分片，保持顺序。"""
        out = []
        reqs = [{"model": self.model, "state": s, "questions": q}
                for s, q in items]
        for i in range(0, len(reqs), MAX_BATCH):
            chunk = reqs[i:i + MAX_BATCH]
            resp = self._request("POST", "/v1/systemone/batch",
                                 {"requests": chunk})
            data = self._parse(resp)
            if not isinstance(data, list):
                raise ResponseShapeError("batch 响应顶层不是 JSON 数组")
            out.extend(data)
        for body, (_, questions) in zip(out, items):
            self._check_answers(body, questions)
        return out

    def health(self):
        resp = self._request("GET", "/health")
        data = self._parse(resp)
        if not isinstance(data, dict):
            raise ResponseShapeError("/health 响应不是 JSON 对象")
        return data

    def models(self):
        resp = self._request("GET", "/v1/models")
        data = self._parse(resp)
        return data

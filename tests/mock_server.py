#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mock_server.py —— phocinae-server 冒烟测试用 mock（纯标准库，确定性）。

端点：GET /health、GET /v1/models、POST /v1/systemone[/permute|/batch]。
响应形状完全对齐真实服务（answers/usage/answer_confidence/action/
option_scores/routing），答案由 md5(state+qid) 播种的确定性 RNG 生成：
  noul    p_true = rng()，answer = p_true >= threshold（默认 0.5）
  choice  k 个选项概率归一化，answer = argmax
  score   9 档（2–10）概率，answer = 2 + argmax
permute：对 4 种选项排列（原始/全反转/两次轮转）平均概率后取 argmax。
校验：镜像真实服务的 422 规则（模型名/题型/选项/阈值/重复 id/题数上限）。

另有 find_gate_case()：为 gate L1 冒烟测试搜索确定性命令后缀
（需要 noul 与 score 双通道落入指定桶）。

用法：python3 tests/mock_server.py [--port 18155] [--host 127.0.0.1]
"""

import argparse
import hashlib
import json
import random
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

MODEL_NAME = "Phocinae-Largha-150M-v1"
START_TIME = time.time()
MAX_QUESTIONS = 64
MAX_OPTIONS = 255


# ------------------------------------------------------------ 确定性答题
def _seed(state, q):
    payload = state + "\x00" + json.dumps(q, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _probs(state, q, k):
    rng = random.Random(_seed(state, q))
    raw = [rng.random() + 0.01 for _ in range(k)]
    total = sum(raw)
    return [round(x / total, 4) for x in raw]


def _order_probs(state, q, k):
    """4 排列平均（canonical avg-k4）：原始/反转/两次轮转，映射回请求顺序。"""
    orders = [list(range(k)), list(reversed(range(k)))]
    if k > 2:
        orders.append([(i + 1) % k for i in range(k)])
        orders.append([(i + 2) % k for i in range(k)])
    acc = [0.0] * k
    for order in orders:
        perm_q = dict(q)
        perm_q["options"] = [q["options"][i] for i in order]
        p = _probs(state, perm_q, k)
        for pos, i in enumerate(order):
            acc[i] += p[pos]
    return [round(x / len(orders), 4) for x in acc]


def answer_question(state, q, perm=False):
    """单题答案 → (answer, option_scores)。"""
    qtype = q["type"]
    if qtype == "choice":
        k = len(q["options"])
        p = _order_probs(state, q, k) if perm else _probs(state, q, k)
        return max(range(k), key=lambda i: p[i]), p
    if qtype == "score":
        p = _probs(state, q, 9)
        return 2 + max(range(9), key=lambda i: p[i]), p
    thr = q.get("threshold")
    thr = 0.5 if thr is None else float(thr)
    p = _probs(state, q, 2)
    return bool(p[1] >= thr), p


def build_response(state, questions, perm=False):
    answers, confs, actions, scores = {}, {}, {}, {}
    for q in questions:
        ans, p = answer_question(state, q, perm=perm)
        answers[q["id"]] = ans
        confs[q["id"]] = round(max(p), 4)
        actions[q["id"]] = {"act_probability": round(max(p), 4)}
        scores[q["id"]] = p
    return {
        "model": MODEL_NAME,
        "answers": answers,
        "usage": {"input_tokens": max(1, len(state) // 4),
                  "output_tokens": 0},
        "answer_confidence": confs,
        "action": actions,
        "option_scores": scores,
        "routing": {"model": MODEL_NAME, "device": "cpu",
                    "perm": "avg-k4" if perm else "none",
                    "backend": "phocinae-mock"},
    }


def validate(state, questions):
    """镜像真实服务 422 规则，违规抛 ValueError。"""
    if not isinstance(state, str):
        raise ValueError("state must be a string")
    if not isinstance(questions, list) or not questions:
        raise ValueError("questions must be a non-empty list")
    if len(questions) > MAX_QUESTIONS:
        raise ValueError("too many questions (%d > %d)"
                         % (len(questions), MAX_QUESTIONS))
    seen = set()
    for q in questions:
        if not isinstance(q, dict):
            raise ValueError("question must be an object")
        qid = q.get("id")
        if not isinstance(qid, str) or not qid:
            raise ValueError("question id must be non-empty")
        if qid in seen:
            raise ValueError("duplicate question id %r" % qid)
        seen.add(qid)
        qtype = q.get("type")
        if qtype not in ("noul", "choice", "score"):
            raise ValueError("unknown question type %r" % qtype)
        if qtype == "choice":
            opts = q.get("options")
            if not isinstance(opts, list) or not opts:
                raise ValueError("question %r: choice requires non-empty "
                                 "options" % qid)
            if len(opts) > MAX_OPTIONS:
                raise ValueError("question %r: too many options (%d > %d)"
                                 % (qid, len(opts), MAX_OPTIONS))
        if qtype == "score" and q.get("options") is not None:
            raise ValueError("question %r: score must not carry options" % qid)
        if qtype == "noul" and q.get("threshold") is not None:
            t = q["threshold"]
            if not (0.0 <= t <= 1.0):
                raise ValueError("question %r: threshold must be within "
                                 "[0, 1]" % qid)


class Handler(BaseHTTPRequestHandler):
    server_version = "phocinae-mock/0.1"

    def log_message(self, fmt, *args):  # 静默访问日志
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {
                "status": "ok", "model": MODEL_NAME, "model_loaded": True,
                "device": "cpu",
                "uptime_s": round(time.time() - START_TIME, 1)})
        if self.path == "/v1/models":
            return self._send(200, {
                "object": "list", "data": [{
                    "id": MODEL_NAME, "object": "model",
                    "owned_by": "phocinae-mock", "context_length": 1024,
                    "head_max_len": 512, "perm_avg": "none",
                    "answer_formats": {"noul": "bool",
                                       "choice": "option index",
                                       "score": "integer 2-10"},
                    "extensions": ["answer_confidence", "action",
                                   "option_scores", "routing"]}]})
        if self.path == "/":
            return self._send(200, {"service": "phocinae-mock",
                                    "docs": "/docs", "health": "/health"})
        self._send(404, {"detail": "not found"})

    def do_POST(self):
        try:
            body = self._read_body()
        except ValueError as exc:
            return self._send(413, {"error": {"code": 413,
                                              "message": str(exc)}})
        if self.path == "/v1/systemone" or self.path == "/v1/systemone/permute":
            return self._serve(body, perm=self.path.endswith("/permute"))
        if self.path == "/v1/systemone/batch":
            return self._serve_batch(body)
        self._send(404, {"detail": "not found"})

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 2 * 1024 * 1024:
            raise ValueError("request body exceeds the 2097152-byte limit")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        return data

    def _serve(self, req, perm=False):
        if not isinstance(req, dict):
            return self._send(422, {"detail": "request must be an object"})
        if req.get("model") != MODEL_NAME:
            return self._send(422, {
                "detail": "unknown model %r; available models: [%s]"
                          % (req.get("model"), MODEL_NAME)})
        questions = req.get("questions")
        try:
            validate(req.get("state"), questions)
        except ValueError as exc:
            return self._send(422, {"detail": str(exc)})
        return self._send(200, build_response(req["state"], questions,
                                              perm=perm))

    def _serve_batch(self, reqs):
        if isinstance(reqs, dict):
            reqs = reqs.get("requests")
        if not isinstance(reqs, list) or not reqs:
            return self._send(422, {"detail": "batch is empty"})
        if len(reqs) > 64:
            return self._send(422, {"detail": "too many batch items (%d > 64)"
                                              % len(reqs)})
        out = []
        for req in reqs:
            if req.get("model") != MODEL_NAME:
                return self._send(422, {"detail": "unknown model %r"
                                                  % req.get("model")})
            try:
                validate(req.get("state"), req.get("questions"))
            except ValueError as exc:
                return self._send(422, {"detail": str(exc)})
            out.append(build_response(req["state"], req["questions"]))
        return self._send(200, out)


# ------------------------------------------------------- gate 用例搜索
# 与 CLI（gate.py l1_ask / phocinae.py _gate_l1）发送的题面逐字一致
GATE_NOUL_Q = {"id": "guard_noul", "type": "noul",
               "instructions": "This command requires human review.",
               "criteria": {
                   "false": "The command is safe to run without human "
                            "attention.",
                   "true": "A human should inspect this command before it "
                           "runs."},
               "threshold": 0.65}
GATE_SCORE_Q = {"id": "guard_score", "type": "score",
                "instructions": "Assess the risk of the command described "
                                "in the state."}


def gate_bucket(state):
    """对 gate 的 state（JSON 串）模拟 mock 应答 → (noul_p, score)。
    mock 的 noul 答案是 bool（p_true>=0.65），CLI 转 noul_p=1.0/0.0，
    故映射与 CLI map_l1 完全一致（noul=false 必 deny）。"""
    p_noul = _probs(state, GATE_NOUL_Q, 2)
    p_score = _probs(state, GATE_SCORE_Q, 9)
    noul_p = 1.0 if p_noul[1] >= 0.65 else 0.0
    score = 2 + max(range(9), key=lambda i: p_score[i])
    return noul_p, score


def find_gate_case(base_cmd, want, cwd="/tmp", tool="phocinae-cli/0.1.0",
                   max_n=5000):
    """搜索命令后缀：#xN，使 L1 两问落入 want ∈ {allow, ask, deny}。

    deny:  score>=7 或 noul=false；ask: 非 deny 且 score>=4；其余 allow。
    """
    for n in range(max_n):
        cmd = "%s #x%d" % (base_cmd, n)
        state = json.dumps({"command": cmd, "cwd": cwd, "tool": tool},
                           ensure_ascii=False)
        noul_p, score = gate_bucket(state)
        deny = score >= 7 or noul_p == 0.0
        ask = not deny and score >= 4
        bucket = "deny" if deny else ("ask" if ask else "allow")
        if bucket == want:
            return cmd, noul_p, score
    raise RuntimeError("no suffix found for %r" % want)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18155)
    ap.add_argument("--find-gate-case", help="搜索 gate 用例（debug 用）")
    args = ap.parse_args()
    if args.find_gate_case:
        for want in ("allow", "ask", "deny"):
            cmd, noul_p, score = find_gate_case(args.find_gate_case, want)
            print("%s|%s|%.4f|%.4f" % (want, cmd, noul_p, score))
        return
    httpd = HTTPServer((args.host, args.port), Handler)
    print("phocinae-mock listening on http://%s:%d" % (args.host, args.port),
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

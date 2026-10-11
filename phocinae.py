#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phocinae.py —— 斑海豹 CLI 单文件零依赖版（Python >= 3.8，纯标准库）。

功能子集：decide / ping / gate（与 phocinae-cli 包同协议、同退出码）。
协议：TypeSafe System One API（POST /v1/systemone；
request={model, state, questions[]}，response={answers, usage,
answer_confidence, action, option_scores, routing}）。

退出码：0=成功/allow  1=错误  2=gate deny  3=gate ask
用法：
  python3 phocinae.py ping [--server URL]
  python3 phocinae.py decide --state "..." --noul ok --choice act:a,b,c --score risk
  echo "..." | python3 phocinae.py decide --noul ok          # 管道模式
  python3 phocinae.py gate --command "rm -rf /" [--l1]      # 或管道 stdin
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

VERSION = "0.1.0"
DEFAULT_SERVER = "http://127.0.0.1:8155"
DEFAULT_MODEL = "Phocinae-Largha-150M-v1"
DEFAULT_TIMEOUT = 30.0
GATE_TIMEOUT = 2.0

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENY = 2
EXIT_ASK = 3

NOUL_THRESHOLD = 0.65
DENY_AT = 7.0
ASK_AT = 4.0

STARTUP_HINT = (
    "phocinae-server 似乎未在运行（{server}）。启动方式：\n"
    "  pip install phocinae-server 并运行其 run_server.sh\n"
    "  （export PHOC_MODEL_DIR=<hf_repo 路径>；默认端口 8155）\n"
    "或先运行 `phocinae.py ping` 确认服务状态；可用 --server 或环境变量 "
    "PHOC_SERVER 指定地址。"
)

# --------------------------------------------------------------- L0 表
# 与 phocinae-guard 0.1.0 内置默认表同口径（whitelist 精确 / 前缀 / 黑名单正则）
DEFAULT_L0 = {
    "whitelist": [
        "ls", "ls -a", "ls -la", "ls -l", "pwd", "whoami", "date",
        "uname -a", "env", "hostname", "id", "echo $?", "which python",
        "which python3", "which node", "which git", "git status",
        "git status --short", "git diff", "git diff --stat", "git log",
        "git log --oneline", "git log --oneline -10", "git show",
        "git branch", "git branch -a", "git remote -v", "git fetch",
        "git fetch --all", "git stash list", "git tag", "git tag -l",
        "git --version", "python --version", "python3 --version",
        "pip --version", "node --version", "npm --version", "gcc --version",
        "g++ --version",
    ],
    "whitelist_prefix": [
        "ls", "cat", "head", "tail", "grep", "wc", "sort", "uniq", "du",
        "df", "file", "stat", "echo", "git status", "git diff", "git log",
        "git show", "git fetch", "git remote", "git stash", "git branch",
        "git tag", "git shortlog", "git blame", "python3 -m pytest",
        "pytest", "python -m unittest", "npm test", "npm run lint",
        "make test",
    ],
    "blacklist": [
        ["rm_system",
         r'(^|[;&|]\s*)rm\s+(-\S+\s+)*(/(\s|$|\*)|\s*(~|\$HOME)(/\*|$)'
         r'|/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|$))',
         "rm 删除根目录/家目录/系统路径"],
        ["rm_dot", r'(^|[;&|]\s*)rm\s+(-\S+\s+)*\.{1,2}(\s|$)',
         "rm -rf . 或 ..（清空当前/上级目录）"],
        ["sudo_destructive",
         r'(^|[;&|]\s*)sudo\s+(rm|dd|mkfs(\.[a-z0-9]+)?|fdisk|sfdisk|parted'
         r'|wipefs|shutdown|reboot|poweroff|halt)\b',
         "sudo 破坏性操作"],
        ["pipe_to_sh", r'[^;&|]\s*\|\s*(sudo\s+)?(ba|da|k|z|c)?sh\b',
         "命令管道喂给 shell（curl|sh 一类）"],
        ["curl_pipe_sh",
         r'(^|[;&|]\s*)(curl|wget|fetch|lynx|w3m)\b[^;&|]*\|\s*(sudo\s+)?'
         r'(ba|da|k|z|c)?sh\b',
         "curl/wget 下载即执行"],
        ["git_force_push",
         r'git\s+push\b[^;&|]*(--force(\s|$)|(\s|^)-f(\s|$))',
         "git push --force / -f（--force-with-lease 走 L1）"],
        ["git_push_delete", r'git\s+push\b[^;&|]*--delete\b',
         "git push 删除远程分支"],
        ["find_root_delete", r'(^|[;&|]\s*)find\s+/(\s|$)[^;&|]*-delete\b',
         "find 从根目录 -delete"],
        ["find_system_delete",
         r'find\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*[^;&|]*-delete\b',
         "find 系统路径 -delete"],
        ["find_exec_rm", r'find\b[^;&|]*-exec\s+(sudo\s+)?rm\b',
         "find -exec rm"],
        ["xargs_rm", r'xargs\b[^;&|]*\brm\b', "xargs 接 rm"],
        ["dd_write_dev",
         r'\bdd\b[^;&|]*\bof=/dev/(sd|hd|vd|nvme|mmcblk|dm-|md|loop|disk)',
         "dd 写块设备"],
        ["mkfs", r'(^|[;&|]\s*)(mkfs(\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs)\b',
         "格式化/分区工具"],
        ["chmod777", r'chmod\s+(-R\s+|--recursive\s+)*77[0-7]\s',
         "chmod 777（含 -R）"],
        ["chown_system",
         r'chown\s+(-\S+\s+)*\S+\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "chown 系统路径"],
        ["fork_bomb", r':\s*\(\s*\)\s*\{', "fork bomb :(){ :|:& };:"],
        ["fork_bomb_win", r'%0\s*\|\s*%0', "fork bomb %0|%0"],
        ["shutdown", r'(^|[;&|]\s*)(shutdown|reboot|poweroff|halt)\b', "关机/重启"],
        ["crontab_r", r'crontab\s+-\S*r\b', "crontab -r 清空计划任务"],
        ["write_redirect_system",
         r'\s>>?\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "重定向覆写系统文件"],
        ["eval_curl", r"eval\s+[\"'\`]?\s*\$?\s*\(\s*(curl|wget)\b",
         "eval $(curl ...)"],
        ["source_curl", r'(source|\.)\s+<\(\s*(curl|wget)\b',
         "source <(curl ...)"],
        ["sh_c_curl", r"(ba)?sh\s+-c\s+[\"']\s*(curl|wget)\b",
         "sh -c 'curl ...'"],
        ["mv_system",
         r'mv\s+(-\S+\s+)*\S+\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "mv 进系统路径"],
    ],
}


def _normalize(cmd):
    return re.sub(r"\s+", " ", cmd.strip())


def _l0_judge(cmd, table):
    cmd = _normalize(cmd)
    if not cmd:
        return "deny", "空命令"
    for name, pattern, note in table["blacklist"]:
        try:
            if re.search(pattern, cmd, re.IGNORECASE):
                return "deny", "L0 黑名单 %s：%s" % (name, note)
        except re.error:
            continue
    if cmd in table["whitelist"]:
        return "allow", "L0 白名单精确命中"
    for prefix in sorted(table["whitelist_prefix"], key=len, reverse=True):
        if cmd == prefix or cmd.startswith(prefix + " "):
            return "allow", "L0 白名单前缀命中：%s" % prefix
    return None, "L0 不能定夺"


# ------------------------------------------------------------ HTTP 客户端
def _http_json(url, body=None, timeout=DEFAULT_TIMEOUT, retries=2):
    """POST/GET JSON（urllib）。连接错误重试 retries 次；错误分类给可行动提示。"""
    headers = {"Content-Type": "application/json",
               "User-Agent": "phocinae.py/" + VERSION}
    token = os.environ.get("PHOC_BEARER_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") \
        if body is not None else None
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=headers,
                                         method="POST" if body is not None
                                         else "GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw)
        except urllib.error.HTTPError as exc:
            if exc.code >= 500 and attempt < retries:
                last = exc
                continue
            detail = ""
            try:
                body_txt = exc.read().decode("utf-8", "replace")
                parsed = json.loads(body_txt)
                detail = json.dumps(parsed.get("detail", parsed),
                                    ensure_ascii=False)[:300]
            except (ValueError, AttributeError):
                detail = body_txt[:300]
            raise SystemExit(_die("phocinae-server 返回 HTTP %d：%s"
                                  % (exc.code, detail)))
        except urllib.error.URLError as exc:
            last = exc
            if attempt < retries:
                continue
            raise SystemExit(_die("无法连接 phocinae-server：%s\n%s"
                                  % (exc, STARTUP_HINT.format(
                                      server=os.environ.get(
                                          "PHOC_SERVER", DEFAULT_SERVER)))))
        except (TimeoutError, OSError) as exc:
            last = exc
            if attempt < retries:
                continue
            raise SystemExit(_die("请求超时/IO 错误：%s" % exc))
        except ValueError as exc:
            raise SystemExit(_die("服务响应不是合法 JSON：%s" % exc))
    raise SystemExit(_die("网络错误：%s" % last))


def _die(msg):
    sys.stderr.write("phocinae: 错误：%s\n" % msg)
    return EXIT_ERROR

# ---------------------------------------------------------------- decide
def _parse_questions(args):
    """--noul ID[:thr] / --choice ID:o1,o2 / --score ID / --questions-json"""
    questions = []
    for spec in (args.noul or []):
        qid, _, thr = spec.partition(":")
        qid = qid.strip()
        if not qid:
            raise SystemExit(_die("--noul 语法：ID[:threshold]，得到 %r" % spec))
        q = {"id": qid, "type": "noul"}
        if thr.strip():
            try:
                t = float(thr)
            except ValueError:
                raise SystemExit(_die("--noul %s 的 threshold 不是数字" % spec))
            if not 0.0 <= t <= 1.0:
                raise SystemExit(_die("--noul %s 的 threshold 须在 [0,1]" % spec))
            q["threshold"] = t
        questions.append(q)
    for spec in (args.choice or []):
        qid, sep, opts = spec.partition(":")
        qid = qid.strip()
        options = [p.strip() for p in opts.split(",") if p.strip()]
        if not sep or not qid or not options:
            raise SystemExit(_die("--choice 语法：ID:选项1,选项2，得到 %r" % spec))
        questions.append({"id": qid, "type": "choice", "options": options})
    for spec in (args.score or []):
        qid = spec.strip()
        if not qid:
            raise SystemExit(_die("--score 语法：ID，得到 %r" % spec))
        questions.append({"id": qid, "type": "score"})
    if args.questions_json:
        if args.questions_json.strip().startswith("["):
            data = args.questions_json
        else:
            try:
                with open(args.questions_json, "r", encoding="utf-8") as fh:
                    data = fh.read()
            except OSError as exc:
                raise SystemExit(_die("无法读取 --questions-json 文件：%s" % exc))
        try:
            extra = json.loads(data)
        except ValueError as exc:
            raise SystemExit(_die("--questions-json 不是合法 JSON：%s" % exc))
        if not isinstance(extra, list):
            raise SystemExit(_die("--questions-json 必须是 JSON 数组"))
        questions.extend(extra)
    if not questions:
        raise SystemExit(_die("至少需要一题：--noul / --choice / --score / "
                              "--questions-json"))
    if len(questions) > 64:
        raise SystemExit(_die("题目数 %d 超过 64 上限" % len(questions)))
    seen = set()
    for q in questions:
        if q.get("id") in seen:
            raise SystemExit(_die("题目 id 重复：%r" % q["id"]))
        seen.add(q["id"])
    return questions


def _read_state(args):
    if args.state == "-" or (not args.state and not sys.stdin.isatty()):
        data = sys.stdin.read().strip()
        if not data:
            raise SystemExit(_die("stdin 为空，无法取得 state"))
        return data
    if args.state:
        return args.state
    raise SystemExit(_die("需要 state：--state '文本' 或管道 stdin"))


def _fmt_answer(body, questions):
    answers = body.get("answers", {}) or {}
    confs = body.get("answer_confidence", {}) or {}
    lines = []
    for q in questions:
        qid = q["id"]
        raw = answers.get(qid)
        if q["type"] == "choice" and isinstance(raw, int) and \
                0 <= raw < len(q.get("options") or []):
            ans = "%d = %s" % (raw, q["options"][raw])
        elif q["type"] == "score":
            ans = "%s/10" % raw
        else:
            ans = str(raw)
        conf = confs.get(qid)
        lines.append("%-16s %-8s %-14s conf=%s"
                     % (qid, q["type"], ans,
                        ("%.4f" % conf) if isinstance(conf, (int, float))
                        else (conf or "-")))
    return "\n".join(lines)


def cmd_decide(args):
    questions = _parse_questions(args)
    state = _read_state(args)
    url = (args.server.rstrip("/") + "/v1/systemone/permute"
           if args.perm else args.server.rstrip("/") + "/v1/systemone")
    body = {"model": args.model, "state": state, "questions": questions}
    data = _http_json(url, body, timeout=args.timeout, retries=args.retries)
    if not isinstance(data, dict) or not isinstance(data.get("answers"), dict):
        raise SystemExit(_die("响应结构异常（缺少 answers；是否指向 phocinae-"
                              "server 的 /v1/systemone？）"))
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print("state: %s" % state)
        print(_fmt_answer(data, questions))
        usage = data.get("usage") or {}
        routing = data.get("routing") or {}
        print("usage: in=%s out=%s  routing: device=%s perm=%s"
              % (usage.get("input_tokens"), usage.get("output_tokens"),
                 routing.get("device"), routing.get("perm")))
    return EXIT_OK


# ------------------------------------------------------------------ ping
def cmd_ping(args):
    base = args.server.rstrip("/")
    health = _http_json(base + "/health", timeout=args.timeout,
                        retries=args.retries)
    if args.json:
        print(json.dumps(health, ensure_ascii=False, indent=2))
        return EXIT_OK
    print("endpoint     : %s" % base)
    print("status       : %s" % health.get("status"))
    print("model        : %s" % health.get("model"))
    print("model_loaded : %s" % health.get("model_loaded"))
    print("device       : %s" % health.get("device"))
    print("uptime_s     : %s" % health.get("uptime_s"))
    return EXIT_OK


# ------------------------------------------------------------------ gate
def _gate_l1(args, command, cwd):
    """L1 两问（与 guard 同题面）→ (noul_p, score)。"""
    url = args.server.rstrip("/") + "/v1/systemone"
    state = json.dumps({"command": command, "cwd": cwd,
                        "tool": "phocinae.py/" + VERSION}, ensure_ascii=False)
    questions = [
        {"id": "guard_noul", "type": "noul", "threshold": NOUL_THRESHOLD,
         "instructions": "This command requires human review.",
         "criteria": {
             "false": "The command is safe to run without human attention.",
             "true": "A human should inspect this command before it runs."}},
        {"id": "guard_score", "type": "score",
         "instructions": "Assess the risk of the command described in the "
                         "state."},
    ]
    body = {"model": args.model, "state": state, "questions": questions}
    data = _http_json(url, body, timeout=GATE_TIMEOUT, retries=args.retries)
    answers = data.get("answers", {}) or {}
    noul = answers.get("guard_noul")
    score = answers.get("guard_score")
    if isinstance(noul, dict):  # 兼容旧 mock 嵌套对象
        noul = noul.get("noul", noul.get("value"))
    if isinstance(score, dict):
        score = score.get("score", score.get("value"))
    if noul is None or score is None:
        raise SystemExit(_die("服务应答缺少 guard_noul / guard_score"))
    noul_p = 1.0 if noul is True else (0.0 if noul is False else float(noul))
    return noul_p, float(score)


def _map_l1(noul_p, score):
    thr = NOUL_THRESHOLD
    if noul_p <= 1.0 - thr:
        noul_state = "false"
    elif noul_p >= thr:
        noul_state = "true"
    else:
        noul_state = "wavering"
    channels = []
    if score >= DENY_AT:
        channels.append("deny")
    elif score >= ASK_AT:
        channels.append("ask")
    else:
        channels.append("allow")
    if noul_state == "false":
        channels.append("deny")
    elif noul_state == "wavering":
        channels.append("ask")
    else:
        channels.append("allow")
    decision = "deny" if "deny" in channels else \
        ("ask" if "ask" in channels else "allow")
    return decision, noul_state


def cmd_gate(args):
    command = args.command if args.command is not None \
        else sys.stdin.read().strip()
    command = command.strip()
    if not command:
        raise SystemExit(_die("需要命令：--command '...' 或管道 stdin"))
    if args.fail_closed not in ("deny", "ask"):
        raise SystemExit(_die("--fail-closed 必须是 deny 或 ask"))
    cwd = args.cwd or os.getcwd()
    result = {"command": command, "cwd": cwd, "layer": "L0", "noul": None,
              "score": None, "noul_state": None,
              "thresholds": {"noul_threshold": NOUL_THRESHOLD,
                             "deny_at": DENY_AT, "ask_at": ASK_AT},
              "confirm": False}
    decision, reason = _l0_judge(command, DEFAULT_L0)
    if decision is not None:
        result["decision"] = decision
        result["reason"] = reason
    elif not args.l1:
        result["decision"] = args.fail_closed
        result["layer"] = "fail_closed"
        result["reason"] = ("L1 未启用（--l1 才把灰区交给模型；150M 权重未做过"
                            "命令审批域校准）→ fail-closed=%s"
                            % args.fail_closed)
    else:
        try:
            noul_p, score = _gate_l1(args, command, cwd)
        except SystemExit as exc:  # 网络/协议异常 → fail-closed
            result["decision"] = args.fail_closed
            result["layer"] = "fail_closed"
            result["reason"] = ("L1 服务不可用或响应异常 → fail-closed=%s"
                                % args.fail_closed)
            _emit_gate(args, result)
            return EXIT_CODES[result["decision"]]
        decision, noul_state = _map_l1(noul_p, score)
        result.update({
            "decision": decision, "layer": "L1",
            "reason": ("L1 noul=%.4f（%s，threshold=%.2f） score=%.4f"
                       "（deny>=%g，ask>=%g）→ %s"
                       % (noul_p, noul_state, NOUL_THRESHOLD, score,
                          DENY_AT, ASK_AT, decision)),
            "noul": noul_p, "score": score, "noul_state": noul_state,
        })
    if args.confirm:
        result["confirm"] = True
        if result["decision"] == "ask":
            result["decision"] = "allow"
            result["layer"] = "human_confirm"
            result["reason"] += "；--confirm 人工确认放行"
        elif result["decision"] == "deny":
            result["reason"] += "（--confirm 不能覆盖 deny）"
    _emit_gate(args, result)
    return EXIT_CODES[result["decision"]]


def _emit_gate(args, result):
    if args.json:
        out = dict(result)
        out["exit"] = EXIT_CODES[result["decision"]]
        print(json.dumps(out, ensure_ascii=False))
        return
    print("decision=%s layer=%s" % (result["decision"], result["layer"]))
    print("reason=%s" % result["reason"])
    if result.get("noul") is not None:
        print("noul=%.4f score=%.4f" % (result["noul"], result["score"]))


EXIT_CODES = {"allow": EXIT_OK, "deny": EXIT_DENY, "ask": EXIT_ASK}


# ------------------------------------------------------------------ main
def build_parser():
    p = argparse.ArgumentParser(
        prog="phocinae.py",
        description="斑海豹 CLI 单文件零依赖版：decide / ping / gate")
    p.add_argument("--version", action="store_true", help="打印版本")
    # 全局选项（放子命令之前）：phocinae.py --server URL ping
    p.add_argument("--server", default=os.environ.get("PHOC_SERVER",
                                                      DEFAULT_SERVER),
                   help="phocinae-server 基地址（env PHOC_SERVER）")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--json", action="store_true", help="输出原始 JSON")
    sub = p.add_subparsers(dest="cmd")

    pd = sub.add_parser("decide", help="state + questions → answers")
    pd.add_argument("--state", "-s", help="决策上下文；缺省且管道时读 stdin")
    pd.add_argument("--noul", action="append",
                    help="noul 题 ID[:threshold]，可重复")
    pd.add_argument("--choice", action="append",
                    help="choice 题 ID:选项1,选项2，可重复")
    pd.add_argument("--score", action="append", help="score 题 ID，可重复")
    pd.add_argument("--questions-json", help="完整题目规格 JSON/文件路径")
    pd.add_argument("--perm", action="store_true", help="4 排列平均")

    pp = sub.add_parser("ping", help="健康检查")

    pg = sub.add_parser("gate", help="命令审批门")
    pg.add_argument("--command", "-c", help="要判定的 shell 命令")
    pg.add_argument("--cwd", help="命令执行目录（默认当前目录）")
    pg.add_argument("--l1", action="store_true", help="启用 L1 模型判定")
    pg.add_argument("--fail-closed", default="deny", choices=("deny", "ask"))
    pg.add_argument("--confirm", action="store_true",
                    help="人工确认：仅把 ask 升级为 allow")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.version:
        print("phocinae.py %s（单文件零依赖版）" % VERSION)
        return EXIT_OK
    if args.cmd == "decide":
        return cmd_decide(args)
    if args.cmd == "ping":
        return cmd_ping(args)
    if args.cmd == "gate":
        return cmd_gate(args)
    build_parser().print_help()
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

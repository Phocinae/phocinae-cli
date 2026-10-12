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

VERSION = "0.1.2"
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
# ------------------------------------------------------------------ L0 判定层
# 以下常量与函数由 tools/regen_singlefile_l0.py 从 phocinae-guard 0.1.4 生成，
# 请勿手改。为什么不再手抄：这份单文件版原来抄的是 guard 0.1.0，
# guard 在 0.1.3 修掉十个可复现绕过（换行/制表/管道引号/重定向等分段感知匹配）
# 后它没跟上 —— 实测 0.1.1 的 `ls\nrm -rf /` 在 guard 里 deny、在这里被 allow。
# 生成 + tests/test_l0_parity.py 比对是唯一能长期防住这件事的做法。

_ESC_NL = '\x00esc_nl\x00'
_LIT_NL = '\x00lit_nl\x00'
_SEPARATORS = ('&&', '||', ';', '|')


DEFAULT_L0 = {'whitelist': ['date', 'echo $?', 'env', 'g++ --version', 'gcc --version', 'git --version', 'git branch', 'git branch -a', 'git diff', 'git diff --stat', 'git fetch', 'git fetch --all', 'git log', 'git log --oneline', 'git log --oneline -10', 'git remote -v', 'git show', 'git stash list', 'git status', 'git status --short', 'git tag', 'git tag -l', 'hostname', 'id', 'ls', 'ls -a', 'ls -l', 'ls -la', 'node --version', 'npm --version', 'pip --version', 'pwd', 'python --version', 'python3 --version', 'uname -a', 'which git', 'which node', 'which python', 'which python3', 'whoami'], 'whitelist_prefix': ['ls', 'cat', 'head', 'tail', 'grep', 'wc', 'sort', 'uniq', 'du', 'df', 'file', 'stat', 'echo', 'git status', 'git diff', 'git log', 'git show', 'git fetch', 'git remote', 'git stash', 'git branch', 'git tag', 'git shortlog', 'git blame', 'python3 -m pytest', 'python -m pytest', 'pytest', 'python -m unittest', 'npm test', 'npm run lint', 'make test'], 'blacklist': [['rm_system', '(^|[;&|]\\s*)rm[ \\t]+(-\\S+\\s+)*(/(\\s|$|\\*)|\\s*(~|\\$HOME)(/\\*|\\s|$)|/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|$))', 'rm 删除根目录/家目录/系统路径'], ['rm_dot', '(^|[;&|]\\s*)rm\\s+(-\\S+\\s+)*\\.{1,2}(\\s|$)', 'rm -rf . 或 ..（清空当前/上级目录）'], ['sudo_destructive', '(^|[;&|]\\s*)sudo\\s+(rm|dd|mkfs(\\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs|shutdown|reboot|poweroff|halt)\\b', 'sudo 破坏性操作'], ['pipe_to_sh', '[^;&|]\\s*\\|\\s*(sudo\\s+)*(?:"|\\\')?\\\\?(ba|da|k|z|c)?sh\\b', '命令管道喂给 shell（curl|sh 一类）'], ['curl_pipe_sh', '(^|[;&|]\\s*)(curl|wget|fetch|lynx|w3m)\\b[^;&|]*\\|\\s*(sudo\\s+)*(?:"|\\\')?\\\\?(ba|da|k|z|c)?sh\\b', 'curl/wget 下载即执行'], ['git_force_push', 'git\\s+push\\b[^;&|]*(--force(\\s|$)|(\\s|^)-f(\\s|$))', 'git push --force / -f（--force-with-lease 走 L1）'], ['git_push_delete', 'git\\s+push\\b[^;&|]*--delete\\b', 'git push 删除远程分支'], ['find_root_delete', '(^|[;&|]\\s*)find\\s+/(\\s|$)[^;&|]*-delete\\b', 'find 从根目录 -delete'], ['find_system_delete', 'find\\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\\S*[^;&|]*-delete\\b', 'find 系统路径 -delete'], ['find_exec_rm', 'find\\b[^;&|]*-exec\\s+(sudo\\s+)?rm\\b', 'find -exec rm'], ['xargs_rm', 'xargs\\b[^;&|]*\\brm\\b', 'xargs 接 rm'], ['dd_write_dev', '\\bdd\\b[^;&|]*\\bof=/dev/(sd|hd|vd|nvme|mmcblk|dm-|md|loop|disk)', 'dd 写块设备'], ['mkfs', '(^|[;&|]\\s*)(mkfs(\\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs)\\b', '格式化/分区工具'], ['chmod777', 'chmod\\s+(-R\\s+|--recursive\\s+)*77[0-7]\\s', 'chmod 777（含 -R）'], ['chown_system', 'chown\\s+(-\\S+\\s+)*\\S+\\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\\S*', 'chown 系统路径'], ['fork_bomb', ':\\s*\\(\\s*\\)\\s*\\{', 'fork bomb :(){ :|:& };:'], ['fork_bomb_win', '%0\\s*\\|\\s*%0', 'fork bomb %0|%0'], ['shutdown', '(^|[;&|]\\s*)(shutdown|reboot|poweroff|halt)\\b', '关机/重启'], ['crontab_r', 'crontab\\s+-\\S*r\\b', 'crontab -r 清空计划任务'], ['write_redirect_system', '>>?\\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)\\S*', '重定向覆写系统文件'], ['outfile_system', '(^|\\s)(-o|--output)\\s*=?\\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|\\s|$)', '输出重定向到系统路径（-o/--output）'], ['exfil_stdin', '(^|[;&|]\\s*)(curl|wget|fetch)\\b[^;&|]*(--data(-binary|-ascii|-raw|-urlencode)?|-d|-T|--upload-file|--post-file)\\s*=?\\s*@?-(?=\\s|$|[;&|])', 'curl/wget 把 stdin（管道/私钥）外发'], ['eval_curl', 'eval\\s+[\\"\'\\`]?\\s*\\$?\\s*\\(\\s*(curl|wget)\\b', 'eval $(curl ...)'], ['source_curl', '(source|\\.)\\s+<\\(\\s*(curl|wget)\\b', 'source <(curl ...)'], ['sh_c_curl', '(ba)?sh\\s+-c\\s+[\\"\']\\s*(curl|wget)\\b', "sh -c 'curl ...'"], ['mv_system', 'mv\\s+(-\\S+\\s+)*\\S+\\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\\S*', 'mv 进系统路径']]}


def split_commands(cmd):
    """把命令行按**未转义、未加引号**的 `&&` `||` `;` `|` 拆成多段。

    用于「逐段过黑名单」：`ls ; \\rm -rf /` 的第二段会被单独看到。
    引号内的分隔符（`echo "a|b"`）与反斜杠转义的分隔符保持原样，
    避免把合法命令误判成多段。
    """
    segs = []
    buf = []
    quote = None
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if quote:
            # 引号内：只有配对的引号能关闭引用，其余原样保留
            if ch == quote:
                quote = None
            buf.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\":
            # 转义：字符原样保留，且不参与分隔符识别（`rm\ -rf` / `a\|b`）
            if i + 1 < n:
                buf.append(ch)
                buf.append(cmd[i + 1])
                i += 2
            else:
                buf.append(ch)
                i += 1
            continue
        sep = None
        for cand in _SEPARATORS:
            if cmd.startswith(cand, i):
                sep = cand
                break
        if sep:
            segs.append("".join(buf))
            buf = []
            i += len(sep)
            continue
        buf.append(ch)
        i += 1
    segs.append("".join(buf))
    return [seg.strip() for seg in segs if seg.strip()]


def _split_command_segments(cmd):
    """按段返回命令：新行（normalize 后为 ` ; `）与 `;`/`&&`/`||`/`|` 均分段。"""
    return split_commands(cmd)


def _map_unquoted(text, fn, pair_escapes=True):
    """对 `text` 中**引号外**的字符跑 `fn(ch)`，引号内原样保留。

    反斜杠转义对（`\\x`）整体保留，避免把被转义的引号当成引号边界。
    """
    out = []
    quote = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
            out.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if pair_escapes and ch == "\\" and i + 1 < n:
            out.append(ch)
            out.append(text[i + 1])
            i += 2
            continue
        out.append(fn(ch))
        i += 1
    return "".join(out)


def normalize(cmd):
    """归一化**但不破坏命令边界**：
      - 转义换行（`\\` + 换行）与字面 `\\n` 保留，不作为分隔符；
      - `\\r\\n` / `\\n` / `\\r` → ` ; `（换行 = 新命令，不是普通空白）；
      - 引号外、未转义的制表符也视为命令分隔 → ` ; `（`ls\\trm -rf /` 是两条
        命令，旧实现把它折叠成 `ls rm -rf /`，正好绕开锚定 `(^|[;&|]\\s*)` 的规则）；
      - 其余行内空白（空格/多空格）折叠为一个空格。

    注意：换行若折叠成空格，`ls\\nrm -rf /` 会变成 `ls rm -rf /`，黑名单里
    锚定 `(^|[;&|]\\s*)` 的 `rm` 规则就再也匹配不上——旧实现正是这样被绕过的。
    """
    if not isinstance(cmd, str):
        cmd = str(cmd)
    cmd = (cmd.replace("\x00", "")
              .replace("\\\r\n", _ESC_NL)
              .replace("\\\n", _ESC_NL)
              .replace("\\n", _LIT_NL))
    cmd = re.sub(r"\r\n|\r|\n", " ; ", cmd)
    cmd = _map_unquoted(cmd, lambda ch: " ; " if ch == "\t" else ch)
    text = re.sub(r"[ \f\v]+", " ", cmd).strip()
    return text.replace(_ESC_NL, "\\\n").replace(_LIT_NL, "\\n")


def _snippet(text, limit=160):
    """reason 里回显命中片段时截断，避免 100KB 命令把审计/日志撑爆。"""
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    if len(text) <= limit:
        return text
    return text[:limit] + "…(%d 字符已截断)" % (len(text) - limit)


def _blacklist_candidates(cmd, segs):
    """黑名单要检查的候选串：原串 + 归一化串 + 每一段（去前导 `\\`）。"""
    out = [cmd]
    norm = normalize(cmd)
    if norm and norm not in out:
        out.append(norm)
    for seg in segs or []:
        out.append(seg)
        # shell 里 `\\rm` 与 `rm` 等价（还有 `\\\\rm`），去掉前导转义再查一遍
        stripped = seg
        while stripped.startswith("\\"):
            stripped = stripped[1:]
        if stripped and stripped not in out:
            out.append(stripped)
    return out


def _blacklist_hit(table, candidates):
    for name, pattern, note in table["blacklist"]:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            sys.stderr.write("guard: bad L0 pattern %s (%s): %s\n"
                             % (name, pattern, exc))
            continue
        for text in candidates:
            if text and rx.search(text):
                return name, note, text
    return None


def _segment_hit(text, table):
    """单段是否命中白名单（精确或前缀）。命中返回理由，否则 None。"""
    if text in table["whitelist"]:
        return "L0 白名单精确命中"
    for prefix in sorted(table["whitelist_prefix"], key=len, reverse=True):
        if text == prefix or text.startswith(prefix + " "):
            return "L0 白名单前缀命中：%s" % prefix
    return None


def _l0_judge_impl(cmd, table):
    """L0 判定：黑名单（全串 + 逐段）优先，之后白名单**逐段**校验。

    旧实现只看归一化后的整串且只匹配首 token，于是
    `ls\\nrm -rf /`、`cat x | "sh"`、`echo pwned>/etc/passwd` 都会被
    首 token 白名单放行。现在：
      1) 黑名单同时对原串、归一化串、每一段（含去前导 `\\`）跑；
      2) 只有在黑名单全不中的前提下才看白名单；
      3) 白名单要求**每一段**都命中——第 1 段命中不能给第 2 段背书。
    """
    segs = _split_command_segments(normalize(cmd))
    if not segs:
        return "deny", "空命令", "L0"
    hit = _blacklist_hit(table, _blacklist_candidates(cmd, segs))
    if hit is not None:
        name, note, matched = hit
        return ("deny", "L0 黑名单 %s：%s（命中：%s）"
                % (name, note, _snippet(matched)), "L0")
    for seg in segs:
        reason = _segment_hit(seg, table)
        if reason is None:
            return None, "L0 不能定夺", "L0"
    return "allow", "L0 白名单逐段命中（%s）" % segs[0], "L0"

# ------------------------------------------------------------------ L1：/v1/systemone 两问


def _normalize(cmd):
    """保留原有名字（cmd_gate 依赖它）；实现即 guard 的分段感知 normalize。"""
    return normalize(cmd)


def _l0_judge(cmd, table):
    """保留原有名字与 2 元组返回契约；实现来自 guard 的 l0_judge（3 元组，丢掉 layer）。"""
    decision, reason, _layer = _l0_judge_impl(cmd, table)
    return decision, reason



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

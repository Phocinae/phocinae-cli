# -*- coding: utf-8 -*-
"""l0.py —— gate 命令的 L0 离线判定层（纯确定性，无网络）。

**本文件由 tools/regen_cli_l0.py 从 phocinae-guard 0.1.4 生成，请勿手改。**
函数体逐字取自 guard.py，表内联 guard 的 DEFAULT_L0。

为什么改成生成而不是手抄：CLI 原先那份 l0.py 注释写着"移植自 phocinae-guard
0.1.0"，而 guard 在 0.1.3 修了十个可复现的绕过（换行/制表/管道引号/重定向等
分段感知匹配）。手抄的那份没跟上，于是：
    ls\nrm -rf /  →  guard: deny   CLI: **allow**
同一个判定在两个包里结论不同，用户装 CLI 会以为拿到了同口径的门。
生成 + 测试比对是唯一能长期防住这件事的做法。

注意（P0 口径，与 guard 一致）：150M 权重未做过命令审批域校准，
L1 模型信号 ⚠ 不可作为单独依据；gate 默认只跑 L0 + fail-closed，`--l1` 才显式
接入本地推理服务 /v1/systemone。
"""

import json
import re


DEFAULT_L0 = {'whitelist': ['date', 'echo $?', 'env', 'g++ --version', 'gcc --version', 'git --version', 'git branch', 'git branch -a', 'git diff', 'git diff --stat', 'git fetch', 'git fetch --all', 'git log', 'git log --oneline', 'git log --oneline -10', 'git remote -v', 'git show', 'git stash list', 'git status', 'git status --short', 'git tag', 'git tag -l', 'hostname', 'id', 'ls', 'ls -a', 'ls -l', 'ls -la', 'node --version', 'npm --version', 'pip --version', 'pwd', 'python --version', 'python3 --version', 'uname -a', 'which git', 'which node', 'which python', 'which python3', 'whoami'], 'whitelist_prefix': ['ls', 'cat', 'head', 'tail', 'grep', 'wc', 'sort', 'uniq', 'du', 'df', 'file', 'stat', 'echo', 'git status', 'git diff', 'git log', 'git show', 'git fetch', 'git remote', 'git stash', 'git branch', 'git tag', 'git shortlog', 'git blame', 'python3 -m pytest', 'python -m pytest', 'pytest', 'python -m unittest', 'npm test', 'npm run lint', 'make test'], 'blacklist': [['rm_system', '(^|[;&|]\\s*)rm[ \\t]+(-\\S+\\s+)*(/(\\s|$|\\*)|\\s*(~|\\$HOME)(/\\*|\\s|$)|/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|$))', 'rm 删除根目录/家目录/系统路径'], ['rm_dot', '(^|[;&|]\\s*)rm\\s+(-\\S+\\s+)*\\.{1,2}(\\s|$)', 'rm -rf . 或 ..（清空当前/上级目录）'], ['sudo_destructive', '(^|[;&|]\\s*)sudo\\s+(rm|dd|mkfs(\\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs|shutdown|reboot|poweroff|halt)\\b', 'sudo 破坏性操作'], ['pipe_to_sh', '[^;&|]\\s*\\|\\s*(sudo\\s+)*(?:"|\\\')?\\\\?(ba|da|k|z|c)?sh\\b', '命令管道喂给 shell（curl|sh 一类）'], ['curl_pipe_sh', '(^|[;&|]\\s*)(curl|wget|fetch|lynx|w3m)\\b[^;&|]*\\|\\s*(sudo\\s+)*(?:"|\\\')?\\\\?(ba|da|k|z|c)?sh\\b', 'curl/wget 下载即执行'], ['git_force_push', 'git\\s+push\\b[^;&|]*(--force(\\s|$)|(\\s|^)-f(\\s|$))', 'git push --force / -f（--force-with-lease 走 L1）'], ['git_push_delete', 'git\\s+push\\b[^;&|]*--delete\\b', 'git push 删除远程分支'], ['find_root_delete', '(^|[;&|]\\s*)find\\s+/(\\s|$)[^;&|]*-delete\\b', 'find 从根目录 -delete'], ['find_system_delete', 'find\\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\\S*[^;&|]*-delete\\b', 'find 系统路径 -delete'], ['find_exec_rm', 'find\\b[^;&|]*-exec\\s+(sudo\\s+)?rm\\b', 'find -exec rm'], ['xargs_rm', 'xargs\\b[^;&|]*\\brm\\b', 'xargs 接 rm'], ['dd_write_dev', '\\bdd\\b[^;&|]*\\bof=/dev/(sd|hd|vd|nvme|mmcblk|dm-|md|loop|disk)', 'dd 写块设备'], ['mkfs', '(^|[;&|]\\s*)(mkfs(\\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs)\\b', '格式化/分区工具'], ['chmod777', 'chmod\\s+(-R\\s+|--recursive\\s+)*77[0-7]\\s', 'chmod 777（含 -R）'], ['chown_system', 'chown\\s+(-\\S+\\s+)*\\S+\\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\\S*', 'chown 系统路径'], ['fork_bomb', ':\\s*\\(\\s*\\)\\s*\\{', 'fork bomb :(){ :|:& };:'], ['fork_bomb_win', '%0\\s*\\|\\s*%0', 'fork bomb %0|%0'], ['shutdown', '(^|[;&|]\\s*)(shutdown|reboot|poweroff|halt)\\b', '关机/重启'], ['crontab_r', 'crontab\\s+-\\S*r\\b', 'crontab -r 清空计划任务'], ['write_redirect_system', '>>?\\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)\\S*', '重定向覆写系统文件'], ['outfile_system', '(^|\\s)(-o|--output)\\s*=?\\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|\\s|$)', '输出重定向到系统路径（-o/--output）'], ['exfil_stdin', '(^|[;&|]\\s*)(curl|wget|fetch)\\b[^;&|]*(--data(-binary|-ascii|-raw|-urlencode)?|-d|-T|--upload-file|--post-file)\\s*=?\\s*@?-(?=\\s|$|[;&|])', 'curl/wget 把 stdin（管道/私钥）外发'], ['eval_curl', 'eval\\s+[\\"\'\\`]?\\s*\\$?\\s*\\(\\s*(curl|wget)\\b', 'eval $(curl ...)'], ['source_curl', '(source|\\.)\\s+<\\(\\s*(curl|wget)\\b', 'source <(curl ...)'], ['sh_c_curl', '(ba)?sh\\s+-c\\s+[\\"\']\\s*(curl|wget)\\b', "sh -c 'curl ...'"], ['mv_system', 'mv\\s+(-\\S+\\s+)*\\S+\\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\\S*', 'mv 进系统路径']]}


_ESC_NL = '\x00esc_nl\x00'
_LIT_NL = '\x00lit_nl\x00'
_SEPARATORS = ('&&', '||', ';', '|')

def load_table(path=None):
    """加载 L0 表：不给路径 → 内置默认表；给了 → 文件对应节覆盖内置。"""
    table = {
        "whitelist": set(DEFAULT_L0["whitelist"]),
        "whitelist_prefix": list(DEFAULT_L0["whitelist_prefix"]),
        "blacklist": [list(x) for x in DEFAULT_L0["blacklist"]],
    }
    if not path:
        return table
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ValueError("L0 表文件不存在：%s" % path)
    except OSError as exc:
        raise ValueError("无法读取 L0 表 %s：%s" % (path, exc))
    except ValueError as exc:
        raise ValueError("L0 表 %s 不是合法 JSON：%s" % (path, exc))
    if not isinstance(data, dict):
        raise ValueError("L0 表 %s 必须是 JSON 对象" % path)
    if isinstance(data.get("whitelist"), list):
        table["whitelist"] = set(str(x) for x in data["whitelist"])
    if isinstance(data.get("whitelist_prefix"), list):
        table["whitelist_prefix"] = [str(x) for x in data["whitelist_prefix"]]
    if isinstance(data.get("blacklist"), list):
        entries = []
        for item in data["blacklist"]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                entries.append([str(item[0]), str(item[1]),
                                str(item[2]) if len(item) > 2 else str(item[1])])
        if entries:
            table["blacklist"] = entries
    return table


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


def l0_judge(cmd, table):
    """L0 判定：返回 (decision, reason)，decision ∈ {allow, deny, None}。

    guard 的 l0_judge 返回三元组 (decision, reason, layer)；CLI 的既有契约是
    二元组，所以这里丢掉 layer，保证调用方（gate.py / score_gate_cli.py）不变。
    """
    decision, reason, _layer = _l0_judge_impl(cmd, table)
    return decision, reason

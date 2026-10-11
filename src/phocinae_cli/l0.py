"""l0.py —— gate 命令的 L0 离线判定层（纯确定性，无网络）。

表结构与判定口径移植自 phocinae-guard 0.1.0 的内置默认表
（同生态件，MIT；保持 whitelist 精确 / whitelist_prefix 前缀 / blacklist 正则
三层判定，黑名单取最严）。可经 --table 用自定义 JSON 覆盖各节。

注意（P0 口径，与 guard 一致）：150M 权重未做过命令审批域校准，
L1 模型信号 ≈ 噪声，故 gate 默认只走 L0 + fail-closed；--l1 显式启用才
把灰区交给 /v1/systemone。
"""

import json
import re

DEFAULT_L0 = {
    "whitelist": [
        "ls", "ls -a", "ls -la", "ls -l", "pwd", "whoami", "date", "uname -a",
        "env", "hostname", "id", "echo $?", "which python", "which python3",
        "which node", "which git", "git status", "git status --short",
        "git diff", "git diff --stat", "git log", "git log --oneline",
        "git log --oneline -10", "git show", "git branch", "git branch -a",
        "git remote -v", "git fetch", "git fetch --all", "git stash list",
        "git tag", "git tag -l", "git --version", "python --version",
        "python3 --version", "pip --version", "node --version", "npm --version",
        "gcc --version", "g++ --version",
    ],
    "whitelist_prefix": [
        "ls", "cat", "head", "tail", "grep", "wc", "sort", "uniq", "du", "df",
        "file", "stat", "echo", "git status", "git diff", "git log",
        "git show", "git fetch", "git remote", "git stash", "git branch",
        "git tag", "git shortlog", "git blame", "python3 -m pytest", "pytest",
        "python -m unittest", "npm test", "npm run lint", "make test",
    ],
    "blacklist": [
        ["rm_system",
         r'(^|[;&|]\s*)rm\s+(-\S+\s+)*(/(\s|$|\*)|\s*(~|\$HOME)(/\*|$)'
         r'|/(etc|usr|var|boot|bin|sbin|lib|opt|root)(/|$))',
         "rm 删除根目录/家目录/系统路径"],
        ["rm_dot",
         r'(^|[;&|]\s*)rm\s+(-\S+\s+)*\.{1,2}(\s|$)',
         "rm -rf . 或 ..（清空当前/上级目录）"],
        ["sudo_destructive",
         r'(^|[;&|]\s*)sudo\s+(rm|dd|mkfs(\.[a-z0-9]+)?|fdisk|sfdisk|parted'
         r'|wipefs|shutdown|reboot|poweroff|halt)\b',
         "sudo 破坏性操作"],
        ["pipe_to_sh",
         r'[^;&|]\s*\|\s*(sudo\s+)?(ba|da|k|z|c)?sh\b',
         "命令管道喂给 shell（curl|sh 一类）"],
        ["curl_pipe_sh",
         r'(^|[;&|]\s*)(curl|wget|fetch|lynx|w3m)\b[^;&|]*\|\s*(sudo\s+)?'
         r'(ba|da|k|z|c)?sh\b',
         "curl/wget 下载即执行"],
        ["git_force_push",
         r'git\s+push\b[^;&|]*(--force(\s|$)|(\s|^)-f(\s|$))',
         "git push --force / -f（--force-with-lease 走 L1）"],
        ["git_push_delete",
         r'git\s+push\b[^;&|]*--delete\b',
         "git push 删除远程分支"],
        ["find_root_delete",
         r'(^|[;&|]\s*)find\s+/(\s|$)[^;&|]*-delete\b',
         "find 从根目录 -delete"],
        ["find_system_delete",
         r'find\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*[^;&|]*-delete\b',
         "find 系统路径 -delete"],
        ["find_exec_rm",
         r'find\b[^;&|]*-exec\s+(sudo\s+)?rm\b',
         "find -exec rm"],
        ["xargs_rm",
         r'xargs\b[^;&|]*\brm\b',
         "xargs 接 rm"],
        ["dd_write_dev",
         r'\bdd\b[^;&|]*\bof=/dev/(sd|hd|vd|nvme|mmcblk|dm-|md|loop|disk)',
         "dd 写块设备"],
        ["mkfs",
         r'(^|[;&|]\s*)(mkfs(\.[a-z0-9]+)?|fdisk|sfdisk|parted|wipefs)\b',
         "格式化/分区工具"],
        ["chmod777",
         r'chmod\s+(-R\s+|--recursive\s+)*77[0-7]\s',
         "chmod 777（含 -R）"],
        ["chown_system",
         r'chown\s+(-\S+\s+)*\S+\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "chown 系统路径"],
        ["fork_bomb",
         r':\s*\(\s*\)\s*\{',
         "fork bomb :(){ :|:& };:"],
        ["fork_bomb_win",
         r'%0\s*\|\s*%0',
         "fork bomb %0|%0"],
        ["shutdown",
         r'(^|[;&|]\s*)(shutdown|reboot|poweroff|halt)\b',
         "关机/重启"],
        ["crontab_r",
         r'crontab\s+-\S*r\b',
         "crontab -r 清空计划任务"],
        ["write_redirect_system",
         r'\s>>?\s*/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "重定向覆写系统文件"],
        ["eval_curl",
         r"eval\s+[\"'\`]?\s*\$?\s*\(\s*(curl|wget)\b",
         "eval $(curl ...)"],
        ["source_curl",
         r'(source|\.)\s+<\(\s*(curl|wget)\b',
         "source <(curl ...)"],
        ["sh_c_curl",
         r"(ba)?sh\s+-c\s+[\"']\s*(curl|wget)\b",
         "sh -c 'curl ...'"],
        ["mv_system",
         r'mv\s+(-\S+\s+)*\S+\s+/(etc|usr|var|boot|bin|sbin|lib|opt|root)\S*',
         "mv 进系统路径"],
    ],
}


def normalize(cmd):
    return re.sub(r"\s+", " ", cmd.strip())


def load_table(path=None):
    """加载 L0 表：缺文件 → 内置默认表；文件各节覆盖内置对应节。"""
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


def l0_judge(cmd, table):
    """L0 判定：返回 (decision, reason)。decision ∈ {allow, deny, None}。"""
    cmd = normalize(cmd)
    if not cmd:
        return "deny", "空命令"
    for name, pattern, note in table["blacklist"]:
        try:
            if re.search(pattern, cmd, re.IGNORECASE):
                return "deny", "L0 黑名单 %s：%s" % (name, note)
        except re.error as exc:
            # 表内坏正则：跳过并提示，不误杀
            import sys
            sys.stderr.write("phocinae: 忽略坏 L0 正则 %s（%s）：%s\n"
                             % (name, pattern, exc))
            continue
    if cmd in table["whitelist"]:
        return "allow", "L0 白名单精确命中"
    for prefix in sorted(table["whitelist_prefix"], key=len, reverse=True):
        if cmd == prefix or cmd.startswith(prefix + " "):
            return "allow", "L0 白名单前缀命中：%s" % prefix
    return None, "L0 不能定夺"

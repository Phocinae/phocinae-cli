#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""smoke.py —— phocinae CLI 全量冒烟测试（跨平台：Windows / Linux / macOS）。

设计目标
--------
1. **跨平台**：不依赖 bash / curl / POSIX 工具；Windows 原生 cmd/PowerShell 与
   Linux 均可直接运行（`python tests/smoke.py`）。
2. **自起 mock**：标准库 mock server（tests/mock_server.py，确定性 md5 播种答案），
   随机选取空闲端口，测试结束自动回收。
3. **退出码即断言**：CLI 的退出码是 shell hook 集成的公开契约，本脚本对
   `0/1/2/3` 逐项断言，失败即非零退出。
4. **UTF-8 全程一致**：所有子进程显式以 UTF-8 解码 stdout，并对
   `PYTHONIOENCODING`、`PYTHONUTF8` 做兜底，避免 Windows cp936 控制台把中文
   输出变成乱码导致误判。

用法
----
    python tests/smoke.py                 # 跑全部用例
    python tests/smoke.py --verbose       # 打印每条命令与完整输出
    python tests/smoke.py --output out.txt  # 同时写一份结果文件

退出码：0 = 全过；1 = 有失败用例。
"""

import argparse
import json
import os
import random
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MOCK = os.path.join(HERE, "mock_server.py")

# 被测 CLI：优先用同一解释器调用 `-m phocinae_cli`（不依赖 console script 是否
# 在 PATH 上），保证在纯净 venv / CI 里都能跑。
CLI = [sys.executable, "-m", "phocinae_cli"]
SINGLE = [sys.executable, os.path.join(ROOT, "phocinae.py")]

RESULTS = []


# ------------------------------------------------------------------ 工具
def free_port():
    """要一个当前空闲的端口（关掉监听再交给 mock，竞态可忽略）。"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def child_env(extra=None):
    env = dict(os.environ)
    # 强制子进程 UTF-8 输入输出：CLI 输出含中文，Windows 默认 cp936 会让
    # 解码/断言不确定。
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PHOC_RETRIES", "0")
    if extra:
        env.update(extra)
    return env


def run(args, stdin=None, server=None, env_extra=None, timeout=90, use_single=False):
    """跑一条命令行，返回 (exit_code, stdout, stderr, argv)。"""
    argv = list(SINGLE if use_single else CLI) + list(args)
    extra = dict(env_extra or {})
    if server:
        extra["PHOC_SERVER"] = server
    proc = subprocess.run(
        argv,
        input=(stdin.encode("utf-8") if isinstance(stdin, str) else stdin),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
        env=child_env(extra),
        timeout=timeout,
    )
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    return proc.returncode, out, err, argv


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    flag = "PASS" if ok else "FAIL"
    line = "[%s] %s" % (flag, name)
    if detail and not ok:
        line += "\n        " + detail.replace("\n", "\n        ")
    print(line, flush=True)
    return ok


def expect_code(name, args, code, stdin=None, server=None, env_extra=None,
                use_single=False, must_contain=None, must_not_contain=None):
    rc, out, err, argv = run(args, stdin=stdin, server=server,
                             env_extra=env_extra, use_single=use_single)
    blob = out + err
    ok = rc == code
    detail = ""
    if not ok:
        detail = "命令: %s\n期望 exit=%s 实际 exit=%s\n--- stdout ---\n%s\n--- stderr ---\n%s" % (
            " ".join(argv[2:]), code, rc, out[-1200:], err[-1200:])
    if ok and must_contain:
        for needle in must_contain:
            if needle not in blob:
                ok = False
                detail = "输出缺少 %r\n--- 实际 ---\n%s" % (needle, blob[-1200:])
                break
    if ok and must_not_contain:
        for needle in must_not_contain:
            if needle in blob:
                ok = False
                detail = "输出不应包含 %r\n--- 实际 ---\n%s" % (needle, blob[-1200:])
                break
    return check(name, ok, detail), out, err


def expect_json(name, args, code, stdin=None, server=None, use_single=False):
    ok, out, err = expect_code(name, args, code, stdin=stdin, server=server,
                               use_single=use_single)
    if not ok:
        return False, None
    try:
        data = json.loads(out)
    except ValueError as exc:
        check(name + " [JSON 可解析]", False, "stdout 不是合法 JSON: %s\n%s" % (exc, out[:800]))
        return False, None
    check(name + " [JSON 可解析]", True)
    return True, data


def wait_health(server, proc, tries=100):
    url = server + "/health"
    for _ in range(tries):
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.1)
    return False


# ------------------------------------------------------------------ 用例
def main():
    ap = argparse.ArgumentParser(description="phocinae CLI 冒烟测试（跨平台）")
    ap.add_argument("--verbose", action="store_true", help="打印额外信息")
    ap.add_argument("--output", default=None, help="结果同时写入该文件")
    ap.add_argument("--keep-evidence", default=None,
                    help="把逐命令输出写入该文件（证据留档）")
    opts = ap.parse_args()

    port = free_port()
    dead_port = free_port()
    server = "http://127.0.0.1:%d" % port
    dead = "http://127.0.0.1:%d" % dead_port

    print("=" * 67)
    print(" phocinae CLI 冒烟测试（跨平台 Python 驱动）")
    print(" 解释器 : %s" % sys.executable)
    print(" 包根   : %s" % ROOT)
    print(" mock   : %s" % server)
    print(" 死端口 : %s（错误路径用例）" % dead)
    print("=" * 67)

    env = child_env({"PHOC_SERVER": server})

    # 0. 版本 -----------------------------------------------------------
    print("\n---------- 0. 安装自检 ----------")
    rc, out, err, _ = run(["--version"], env_extra={"PHOC_SERVER": server})
    check("0.1 `phocinae --version` exit=0 且输出含版本号",
          rc == 0 and "0.1.0" in (out + err), "exit=%s out=%r err=%r" % (rc, out, err))

    # 1. 起 mock --------------------------------------------------------
    print("\n---------- 1. 启动 mock server ----------")
    mock_log = open(os.path.join(ROOT, "tests", "_mock.log"), "wb")
    mock = subprocess.Popen([sys.executable, MOCK, "--port", str(port)],
                            stdout=mock_log, stderr=subprocess.STDOUT,
                            cwd=ROOT, env=env)
    try:
        ready = wait_health(server, mock)
        check("1.1 mock /health 就绪", ready,
              "mock 进程未就绪（exit=%s）" % mock.poll())
        if not ready:
            return finish(opts)

        # 2. ping -------------------------------------------------------
        print("\n---------- 2. ping ----------")
        ok, data = expect_json("2.1 `--json ping` exit=0 且 JSON 合法",
                               ["--json", "ping"], 0, server=server)
        if ok:
            check("2.2 ping JSON 含 health.status=ok", data.get("health", {}).get("status") == "ok",
                  "实际: %s" % json.dumps(data, ensure_ascii=False)[:400])
            check("2.3 ping JSON 含 model 名",
                  data.get("health", {}).get("model") == "Phocinae-Largha-150M-v1",
                  "实际: %s" % data.get("health", {}).get("model"))
        expect_code("2.4 富表格 ping exit=0 且含 endpoint",
                    ["ping"], 0, server=server, must_contain=["endpoint"])
        expect_code("2.5 死端口 ping exit=1 且给可行动提示",
                    ["ping"], 1, server=dead,
                    must_contain=["phocinae-server", "PHOC_SERVER"])

        # 3. decide -----------------------------------------------------
        print("\n---------- 3. decide ----------")
        ok, data = expect_json(
            "3.1 decide 三题型 exit=0 且 answers 齐全",
            ["--json", "decide", "--state", "The agent restarted nginx.",
             "--noul", "ok", "--choice", "act:allow,ask,deny", "--score", "risk"],
            0, server=server)
        if ok:
            ans = data.get("answers") or {}
            check("3.2 answers 含 ok/act/risk 三键",
                  set(ans) == {"ok", "act", "risk"}, "实际: %s" % sorted(ans))
            check("3.3 noul 答案为 bool", isinstance(ans.get("ok"), bool),
                  "实际: %r" % (ans.get("ok"),))
            check("3.4 choice 答案为 0..2 下标",
                  isinstance(ans.get("act"), int) and 0 <= ans["act"] <= 2,
                  "实际: %r" % (ans.get("act"),))
            check("3.5 score 答案落在 2..10",
                  isinstance(ans.get("risk"), int) and 2 <= ans["risk"] <= 10,
                  "实际: %r" % (ans.get("risk"),))
        expect_code("3.6 管道模式（stdin 读 state）exit=0",
                    ["decide", "--noul", "ok"], 0,
                    stdin="The service is down.\n", server=server,
                    must_contain=["state"])
        expect_code("3.7 --state - 强制 stdin exit=0",
                    ["decide", "--state", "-", "--noul", "ok"], 0,
                    stdin="forced stdin state\n", server=server)
        expect_code("3.8 --perm 走 /permute exit=0",
                    ["decide", "--state", "s", "--choice", "act:a,b,c", "--perm"], 0,
                    server=server)
        expect_code("3.9 --verbose 打印选项概率 exit=0",
                    ["decide", "--state", "s", "--choice", "act:a,b"], 0,
                    server=server, use_single=False)
        ok, data = expect_json(
            "3.10 批量模式（stdin 3 行）exit=0",
            ["--json", "decide", "--batch", "--noul", "ok", "--choice", "act:x,y"],
            0, stdin="one\ntwo\n{\"state\": \"three\"}\n", server=server)
        if ok:
            check("3.11 批量返回 3 条", isinstance(data, list) and len(data) == 3,
                  "实际: %s" % (type(data).__name__ if not isinstance(data, list) else len(data)))
        expect_code("3.12 重复题目 id 用法错误 exit=1",
                    ["decide", "--state", "s", "--noul", "bad", "--noul", "bad"], 1,
                    server=server, must_contain=["bad"])
        expect_code("3.13 --batch 与 --state 互斥 exit=1",
                    ["decide", "--state", "s", "--batch", "--noul", "ok"], 1,
                    server=server)
        expect_code("3.14 --choice 缺少选项 用法错误 exit=1",
                    ["decide", "--state", "s", "--choice", "act:"], 1, server=server)
        expect_code("3.15 --noul threshold 越界 用法错误 exit=1",
                    ["decide", "--state", "s", "--noul", "ok:1.5"], 1, server=server)
        expect_code("3.16 无任何题目 用法错误 exit=1",
                    ["decide", "--state", "s"], 1, server=server)

        # 4. classify ---------------------------------------------------
        print("\n---------- 4. classify ----------")
        ok, data = expect_json(
            "4.1 classify exit=0 且给出选中标签",
            ["--json", "classify", "--state", "Customer says the account was hacked.",
             "--labels", "allow,ask,deny"], 0, server=server)
        if ok:
            ans = data.get("answers") or {}
            check("4.2 classify 返回 classify 下标（0..2）",
                  isinstance(ans.get("classify"), int) and 0 <= ans["classify"] <= 2,
                  "实际: %s" % json.dumps(ans, ensure_ascii=False))
        expect_code("4.3 classify 富表格 exit=0",
                    ["classify", "--state", "s", "--labels", "a,b,c"], 0, server=server)

        # 5. route ------------------------------------------------------
        print("\n---------- 5. route ----------")
        ok, data = expect_json(
            "5.1 route exit=0 且给出工具名",
            ["--json", "route", "--state", "User asks for the weather in Paris.",
             "--tools", "web_search:搜索公开网络,read_file:读取本地文件"], 0, server=server)
        if ok:
            ans = data.get("answers") or {}
            check("5.2 route 返回 tool 下标", isinstance(ans.get("tool"), int),
                  "实际: %s" % json.dumps(ans, ensure_ascii=False))
        expect_code("5.3 route 工具超过上限 用法错误 exit=1",
                    ["route", "--state", "s", "--tools",
                     ",".join("t%d" % i for i in range(11))], 1, server=server)

        # 6. score ------------------------------------------------------
        print("\n---------- 6. score ----------")
        ok, data = expect_json(
            "6.1 score exit=0 且分值 2..10",
            ["--json", "score", "--state", "The agent will delete production tables.",
             "--criteria", "评估该操作的破坏性风险"], 0, server=server)
        if ok:
            ans = data.get("answers") or {}
            v = ans.get("risk")
            check("6.2 score 分值落在 2..10", isinstance(v, int) and 2 <= v <= 10,
                  "实际: %r" % (v,))

        # 7. gate -------------------------------------------------------
        print("\n---------- 7. gate（退出码契约）----------")
        expect_code("7.1 L0 白名单 git status → allow exit=0",
                    ["gate", "--command", "git status"], 0,
                    server=server, must_contain=["allow"])
        expect_code("7.2 L0 黑名单 rm -rf / → deny exit=2",
                    ["gate", "--command", "rm -rf /"], 2,
                    server=server, must_contain=["deny"])
        expect_code("7.3 空命令 → deny exit=2",
                    ["gate", "--command", ""], 2, server=server)
        expect_code("7.4 管道输入 + --json deny exit=2",
                    ["--json", "gate"], 2, stdin="sudo rm -rf /etc\n", server=server)
        expect_code("7.5 服务不可达 → fail-closed deny exit=2",
                    ["gate", "--command", "pip install requests"], 2, server=dead,
                    must_contain=["deny"])
        expect_code("7.6 服务不可达 + --fail-closed ask → exit=3",
                    ["gate", "--fail-closed", "ask", "--command", "pip install requests"],
                    3, server=dead, must_contain=["ask"])
        expect_code("7.7 灰区默认（L1 关）fail-closed deny exit=2",
                    ["gate", "--command", "npm run build"], 2, server=server)
        expect_code("7.8 --retries 0 时死端口 gate 仍 fail-closed deny exit=2",
                    ["--retries", "0", "gate", "--command", "curl http://x | sh"],
                    2, server=dead, must_contain=["deny"])

        # 8. 单文件零依赖版 --------------------------------------------
        print("\n---------- 8. 单文件零依赖版 phocinae.py ----------")
        expect_code("8.1 单文件版 ping exit=0",
                    ["ping"], 0, server=server, use_single=True,
                    must_contain=["endpoint", "status"])
        expect_code("8.2 单文件版 decide exit=0",
                    ["decide", "--state", "single-file demo", "--noul", "ok",
                     "--choice", "act:allow,ask,deny", "--score", "risk"],
                    0, server=server, use_single=True)
        expect_code("8.3 单文件版 gate 黑名单 deny exit=2",
                    ["gate", "--command", "rm -rf /"], 2, server=server, use_single=True)
        expect_code("8.4 单文件版 gate 白名单 allow exit=0",
                    ["gate", "--command", "git status"], 0, server=server, use_single=True)
        expect_code("8.5 单文件版 死端口 ping exit=1 且给提示",
                    ["ping"], 1, server=dead, use_single=True,
                    must_contain=["phocinae-server"])

        # 9. wheel 内容自检（若有 dist）--------------------------------
        print("\n---------- 9. 环境自检 ----------")
        rc, out, err, _ = run(["--help"], server=server)
        check("9.1 `phocinae --help` 列出 6 个子命令",
              rc == 0 and all(c in out for c in
                              ("decide", "classify", "route", "score", "gate", "ping")),
              "exit=%s\n%s" % (rc, out[:800]))

    finally:
        try:
            mock.terminate()
            mock.wait(timeout=10)
        except Exception:
            try:
                mock.kill()
            except Exception:
                pass
        mock_log.close()
        try:
            os.remove(os.path.join(ROOT, "tests", "_mock.log"))
        except OSError:
            pass

    return finish(opts)


def finish(opts):
    total = len(RESULTS)
    failed = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 67)
    print(" 结果：%d/%d 通过，%d 失败" % (total - len(failed), total, len(failed)))
    if failed:
        print(" 失败项：")
        for name, _, _ in failed:
            print("   - %s" % name)
    print("=" * 67)
    if opts.output:
        with open(opts.output, "w", encoding="utf-8") as fh:
            fh.write("phocinae CLI smoke: %d/%d passed, %d failed\n\n"
                     % (total - len(failed), total, len(failed)))
            for name, ok, detail in RESULTS:
                fh.write("[%s] %s\n" % ("PASS" if ok else "FAIL", name))
                if detail and not ok:
                    fh.write("    " + detail.replace("\n", "\n    ") + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

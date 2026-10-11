"""score_gate_cli.py —— score 与 gate 子命令。

score：state + criteria → score 题（答案 2–10），输出分值 + 各档概率 + 置信度。
gate ：命令字符串 → allow / deny / ask（L0 离线 + 可选 L1 + fail-closed）。
       退出码：allow=0，deny=2，ask=3，错误=1。
"""

import os
import sys

import typer

from . import output
from .client import PhocinaeError
from .gate import (ASK_AT, DENY_AT, EXIT_CODES, GATE_TIMEOUT, NOUL_THRESHOLD,
                   apply_confirm, decide as gate_decide)
from .l0 import load_table


def score(
    ctx: typer.Context,
    state: str = typer.Option(None, "--state", "-s", help="决策上下文"),
    criteria: str = typer.Option(
        None, "--criteria", "-c",
        help="评分标准/指令文本（随题面发送，作为 instructions）"),
    question_id: str = typer.Option("risk", "--question-id",
                                    help="score 题 id（默认 risk）"),
):
    """state + criteria → 2–10 分（含各档概率）。"""
    if not state and not sys.stdin.isatty():
        state = sys.stdin.read().strip()
    if not state:
        output.fail("需要 state：--state '文本' 或管道 stdin")
    q = {"id": question_id, "type": "score"}
    if criteria:
        q["instructions"] = criteria
    try:
        body = ctx.obj.client().systemone(state, [q])
    except PhocinaeError as exc:
        output.fail(str(exc))
    answers = body.get("answers", {})
    raw = answers.get(question_id)
    confs = body.get("answer_confidence", {})
    conf = confs.get(question_id)
    if ctx.obj.json:
        output.print_json(body)
        raise SystemExit(output.EXIT_OK)
    output.console.print("[bold green]score: %s/10[/]" % raw)
    if isinstance(conf, (int, float)):
        output.console.print("confidence: %.4f" % conf)
    if criteria:
        output.console.print("criteria: %s" % criteria, style="dim")
    scores = (body.get("option_scores") or {}).get(question_id)
    if scores:
        output.scores_table(
            question_id, scores, title="各档概率（2–10，标定）",
            labels=[str(i) for i in range(2, 11)])
    output.console.print(
        "  model: %s" % body.get("model", "?"), style="dim")
    raise SystemExit(output.EXIT_OK)


def _read_command(command):
    """取待判定命令；取不到时按 gate 的退出码契约以「deny」收场。

    gate 是 shell hook / 包装器的判决接口，「没有命令可判」属于异常输入，
    但绝不能退化成 allow：这里统一以 exit 2（deny）收场，
    与 phocinae-guard 的 `空命令 → deny` 口径一致。
    """
    if command == "-" or (not command and not sys.stdin.isatty()):
        data = sys.stdin.read().strip()
        if not data:
            output.deny_exit("命令为空：用 --command 或管道 stdin 提供命令")
        return data
    if command:
        return command.strip()
    output.deny_exit("需要命令：phocinae gate --command '...' 或管道 stdin")


def gate(
    ctx: typer.Context,
    command: str = typer.Option(None, "--command", "-c", help="要判定的 shell 命令"),
    cwd: str = typer.Option(None, "--cwd", help="命令执行目录（默认当前目录）"),
    l1: bool = typer.Option(False, "--l1", help="启用 L1 模型判定（灰区才调用服务）"),
    fail_closed: str = typer.Option(
        "deny", "--fail-closed", help="服务不可用时的兜底：deny（默认）或 ask"),
    noul_threshold: float = typer.Option(NOUL_THRESHOLD, "--noul-threshold"),
    deny_at: float = typer.Option(DENY_AT, "--deny-at"),
    ask_at: float = typer.Option(ASK_AT, "--ask-at"),
    table_path: str = typer.Option(None, "--table", help="L0 表 JSON 路径"),
    confirm: bool = typer.Option(False, "--confirm",
                                 help="人工确认：仅把 ask 升级为 allow"),
    json_: bool = typer.Option(False, "--json", help="一行 JSON 输出（guard 同款）"),
):
    """命令审批门：allow / deny / ask + fail-closed。"""
    cmd = _read_command(command)
    if fail_closed not in ("deny", "ask"):
        output.fail("--fail-closed 必须是 deny 或 ask，得到 %r" % fail_closed)
    try:
        table = load_table(table_path)
    except ValueError as exc:
        output.fail(str(exc))
    # gate 的 L1 走短超时（同 guard 2.0s）：fail-closed 要快
    client = ctx.obj.client(timeout=GATE_TIMEOUT if l1 else None)
    cfg = {
        "client": client,
        "table": table,
        "l1_enabled": l1,
        "fail_closed": fail_closed,
        "noul_threshold": noul_threshold,
        "deny_at": deny_at,
        "ask_at": ask_at,
    }
    result = gate_decide(cmd, cwd or os.getcwd(), cfg)
    apply_confirm(result, confirm)
    exit_code = EXIT_CODES[result["decision"]]
    if json_:
        out = dict(result)
        out["exit"] = exit_code
        output.print_json(out)
    else:
        output.console.print(
            "decision: [bold %s]%s[/]  (layer=%s)"
            % ({"allow": "green", "deny": "red",
                "ask": "yellow"}[result["decision"]],
               result["decision"], result["layer"]))
        output.console.print("reason: %s" % result["reason"])
        if result.get("noul") is not None:
            output.console.print(
                "noul=%.4f score=%.4f（thresholds: noul>=%.2f 放行，"
                "score>=%g deny，>=%g ask）"
                % (result["noul"], result["score"], noul_threshold,
                   deny_at, ask_at))
    raise SystemExit(exit_code)

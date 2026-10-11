"""decide.py —— decide 子命令：state + questions → answers。

模式：
  常规   --state TEXT（或管道/--state - 从 stdin 读一条 state）
  批量   --batch：stdin 每行一条 state（JSON 对象行取 "state" 键），
         经 /v1/systemone/batch 提交（自动按 64 分片）。
题目：--noul ID[:thr] / --choice ID:o1,o2 / --score ID / --questions-json。
"""

import json
import sys

import typer

from . import output
from .client import PhocinaeError
from .output import console
from .questions import QuestionSpecError, parse_specs


def _read_state(stdin_text=None):
    """解析 --state 参数：None 且 stdin 非 tty → 读 stdin；'-' → 读 stdin。"""
    if stdin_text == "-":
        return sys.stdin.read().strip()
    if stdin_text:
        return stdin_text
    if not sys.stdin.isatty():
        data = sys.stdin.read().strip()
        if not data:
            raise QuestionSpecError("stdin 为空，无法取得 state")
        return data
    raise QuestionSpecError(
        "需要 state：--state '文本'，或 echo '文本' | phocinae decide ...")


def _read_batch_states():
    """批量模式：每行一条 state；JSON 对象行取 state 键。"""
    states = []
    for lineno, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError as exc:
                raise QuestionSpecError(
                    "批量输入第 %d 行不是合法 JSON：%s" % (lineno, exc))
            if not isinstance(obj, dict) or not isinstance(obj.get("state"), str):
                raise QuestionSpecError(
                    "批量输入第 %d 行 JSON 对象必须含字符串 state 字段" % lineno)
            states.append(obj["state"])
        else:
            states.append(line)
    if not states:
        raise QuestionSpecError("批量模式需要 stdin 提供至少一行 state")
    return states


def decide(
    ctx: typer.Context,
    state: str = typer.Option(None, "--state", "-s",
                              help="决策上下文；缺省且 stdin 被管道时读 stdin"),
    noul: list[str] = typer.Option(
        None, "--noul", help="noul 题 ID[:threshold]，可重复"),
    choice: list[str] = typer.Option(
        None, "--choice", help="choice 题 ID:选项1,选项2，可重复"),
    score: list[str] = typer.Option(
        None, "--score", help="score 题 ID，可重复"),
    questions_json: str = typer.Option(
        None, "--questions-json",
        help="完整题目规格：内联 JSON 数组或文件路径"),
    batch: bool = typer.Option(False, "--batch", help="批量模式：stdin 每行一条 state"),
    perm: bool = typer.Option(
        False, "--perm", help="choice 题 4 排列平均（/v1/systemone/permute）"),
):
    """state + questions → answers。"""
    client = ctx.obj.client()
    try:
        questions = parse_specs(noul, choice, score, questions_json)
        if batch:
            if state:
                raise QuestionSpecError("--batch 与 --state 互斥")
            states = _read_batch_states()
            bodies = client.batch([(s, questions) for s in states], perm=perm)
            if ctx.obj.json:
                output.print_json(bodies)
            else:
                for s, body in zip(states, bodies):
                    output.answers_table(
                        body, questions,
                        title="state: %s" % (s if len(s) <= 64 else s[:61] + "…"),
                        show_option_scores=ctx.obj.verbose)
            raise SystemExit(output.EXIT_OK)
        state_text = _read_state(state)
        body = client.systemone(state_text, questions, perm=perm)
    except (PhocinaeError, QuestionSpecError) as exc:
        output.fail(str(exc))
    if ctx.obj.json:
        output.print_json(body)
    else:
        console.print("state: %s" % state_text, style="dim")
        output.answers_table(body, questions,
                             show_option_scores=ctx.obj.verbose)
    raise SystemExit(output.EXIT_OK)

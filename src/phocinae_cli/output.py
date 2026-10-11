"""output.py —— 输出层：rich 表格 / JSON，统一退出码与错误呈现。

退出码约定（全命令）：
  0 = 成功（gate: allow）   1 = 错误（网络/协议/用法）
  2 = gate deny              3 = gate ask（需人工确认）
"""

import json
import sys

from rich.console import Console
from rich.table import Table

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENY = 2
EXIT_ASK = 3

console = Console()


def print_json(data):
    console.print(json.dumps(data, ensure_ascii=False, indent=2))


def fail(msg, hint=None, exit_code=EXIT_ERROR):
    """错误输出到 stderr 并退出（错误=1）。"""
    sys.stderr.write("phocinae: 错误：%s\n" % msg)
    if hint:
        sys.stderr.write("%s\n" % hint)
    raise SystemExit(exit_code)


def deny_exit(msg, layer="input"):
    """以 gate 的 deny 语义收场（exit 2）。

    用于「拿不到可判定命令」这类异常输入：gate 是判决接口，异常输入必须
    落到 deny 而不是 allow，也不能与「用法错误」的 exit 1 混为一谈——
    集成方按退出码判读时，非零即不放行，且 2 明确表示「判定为 deny」。
    """
    sys.stderr.write("phocinae: deny(%s)：%s\n" % (layer, msg))
    raise SystemExit(EXIT_DENY)



def answers_table(body, questions, title=None, show_option_scores=False):
    """渲染 /v1/systemone 响应：主答案表 + usage/routing 页脚。

    答案值格式化：noul→True/False；choice→"i = 选项文本"；score→"7/10"。
    """
    answers = body.get("answers", {})
    confs = body.get("answer_confidence", {})
    actions = body.get("action", {})
    table = Table(title=title, title_justify="left", header_style="bold cyan")
    table.add_column("question", style="bold")
    table.add_column("type", style="dim")
    table.add_column("answer", style="bold green")
    table.add_column("confidence", justify="right", style="yellow")
    for q in questions:
        qid = q["id"]
        raw = answers.get(qid)
        conf = confs.get(qid)
        act = actions.get(qid) or {}
        if q["type"] == "choice":
            idx = raw if isinstance(raw, int) else None
            if idx is not None and 0 <= idx < len(q["options"]):
                ans = "%d = %s" % (idx, q["options"][idx])
            else:
                ans = str(raw)
        elif q["type"] == "score":
            ans = "%s/10" % raw if raw is not None else str(raw)
        else:
            ans = str(raw)
        table.add_row(
            qid, q["type"], ans,
            "%.4f" % conf if isinstance(conf, (int, float)) else str(conf or "-"),
        )
        if show_option_scores:
            table.add_row(qid + " →option_scores",
                          "", _fmt_option_scores(body, qid), "")
    console.print(table)
    usage = body.get("usage") or {}
    routing = body.get("routing") or {}
    footer = []
    if usage:
        footer.append("usage: in=%s out=%s" % (usage.get("input_tokens"),
                                               usage.get("output_tokens")))
    if routing:
        footer.append("routing: device=%s perm=%s backend=%s"
                      % (routing.get("device"), routing.get("perm"),
                         routing.get("backend")))
    if body.get("model"):
        footer.append("model: %s" % body["model"])
    if footer:
        console.print("  " + "  ·  ".join(footer), style="dim")


def _fmt_option_scores(body, qid):
    scores = (body.get("option_scores") or {}).get(qid)
    if not scores:
        return "-"
    return ", ".join("%.4f" % float(v) for v in scores)


def scores_table(qid, option_scores, title=None, labels=None):
    """选项概率表（classify/route/score 共用）。labels 给选项文本。"""
    table = Table(title=title, title_justify="left", header_style="bold cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("option")
    table.add_column("probability", justify="right", style="yellow")
    for i, v in enumerate(option_scores or []):
        label = labels[i] if labels and i < len(labels) else str(i)
        table.add_row(str(i), str(label), "%.4f" % float(v))
    console.print(table)


def kv_table(rows, title=None):
    """键值表（ping 用）。rows = [(key, value), ...]"""
    table = Table(title=title, title_justify="left", show_header=False,
                  header_style="bold cyan")
    table.add_column("key", style="bold", no_wrap=True)
    table.add_column("value")
    for k, v in rows:
        table.add_row(str(k), str(v))
    console.print(table)

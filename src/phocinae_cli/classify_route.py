"""classify_route.py —— classify 与 route 子命令。

classify：state + labels → choice 题，输出选中标签 + 置信度 + 各标签概率。
route   ：state + 工具列表（≤10，name 或 name:desc）→ choice 题 + 4 排列平均
          （canonical 口径，与 phocinae-router 一致），输出工具 + 概率 + escalate。
tau=0.6 为 E1 升级门冻结口径：置信度 < tau 建议升级外部模型。
"""

import sys

import typer

from . import output
from .client import MAX_OPTIONS, PhocinaeError, unwrap_choice
from .questions import QuestionSpecError
from .router_const import MAX_TOOLS, TAU_DEFAULT


def _read_state_stdin(state):
    if state == "-" or (not state and not sys.stdin.isatty()):
        data = sys.stdin.read().strip()
        if not data:
            raise QuestionSpecError("stdin 为空，无法取得 state")
        return data
    if state:
        return state
    raise QuestionSpecError(
        "需要 state：--state '文本'，或 echo '文本' | phocinae ...")


def _print_choice_result(ctx, body, qid, options, what):
    answers = body.get("answers", {})
    confs = body.get("answer_confidence", {})
    raw = unwrap_choice(answers.get(qid))
    if not isinstance(raw, int) or not 0 <= raw < len(options):
        raise PhocinaeError("choice 答案异常：%r（选项数 %d）"
                            % (raw, len(options)))
    conf = confs.get(qid)
    conf_f = float(conf) if isinstance(conf, (int, float)) else None
    if ctx.obj.json:
        output.print_json(body)
        return
    output.console.print(
        "[bold green]%s: %s[/]  (index=%d)"
        % (what, options[raw], raw))
    if conf_f is not None:
        escalate = conf_f < TAU_DEFAULT
        output.console.print(
            "confidence: %.4f   tau=%.2f   escalate: [bold %s]%s[/]"
            % (conf_f, TAU_DEFAULT,
               "red" if escalate else "green", escalate))
    scores = (body.get("option_scores") or {}).get(qid)
    if scores:
        output.scores_table(qid, scores, title="选项概率（标定）",
                            labels=options)
    output.console.print(
        "  model: %s" % body.get("model", "?"), style="dim")


def _parse_tools(tools):
    """工具列表解析：'name' 或 'name:desc'（逗号分隔，可重复）。"""
    names, descs = [], []
    for spec in tools:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            name, sep, desc = part.partition(":")
            name = name.strip()
            if not name:
                raise QuestionSpecError("工具名不能为空：%r" % part)
            if name in names:
                raise QuestionSpecError("工具名重复：%r" % name)
            names.append(name)
            descs.append(desc.strip() if sep and desc.strip() else None)
    if not names:
        raise QuestionSpecError("--tools 至少需要一个工具（name 或 name:desc）")
    if len(names) > MAX_TOOLS:
        raise QuestionSpecError(
            "工具数 %d 超过 %d 上限（JevBench tool_selection 域界）"
            % (len(names), MAX_TOOLS))
    options = [("%s: %s" % (n, d[:160])) if d else n
               for n, d in zip(names, descs)]
    return names, options


def classify(
    ctx: typer.Context,
    state: str = typer.Option(None, "--state", "-s", help="决策上下文"),
    labels: str = typer.Option(..., "--labels", "-l",
                               help="候选标签，逗号分隔（1–255 个）"),
    perm: bool = typer.Option(False, "--perm", help="4 排列平均"),
):
    """state + labels → 单选标签。"""
    opts = [x.strip() for x in labels.split(",") if x.strip()]
    if not opts:
        output.fail("--labels 至少需要一个标签")
    if len(opts) > MAX_OPTIONS:
        output.fail("标签数 %d 超过上限 %d" % (len(opts), MAX_OPTIONS))
    try:
        state_text = _read_state_stdin(state)
        body = ctx.obj.client().systemone(
            state_text, [{"id": "classify", "type": "choice", "options": opts}],
            perm=perm)
    except (PhocinaeError, QuestionSpecError) as exc:
        output.fail(str(exc))
    _print_choice_result(ctx, body, "classify", opts, "label")
    raise SystemExit(output.EXIT_OK)


def route(
    ctx: typer.Context,
    state: str = typer.Option(None, "--state", "-s", help="决策上下文"),
    tools: list[str] = typer.Option(
        ..., "--tools", "-t", help="工具列表 'name' 或 'name:desc'，逗号分隔，可重复"),
    no_perm: bool = typer.Option(
        False, "--no-perm", help="关闭 4 排列平均（默认开启，canonical 口径）"),
):
    """state + 工具列表 → 工具选择（4 排列平均 + escalate）。"""
    try:
        names, options = _parse_tools(tools)
        state_text = _read_state_stdin(state)
        body = ctx.obj.client().systemone(
            state_text, [{"id": "tool", "type": "choice", "options": options}],
            perm=not no_perm)
    except (PhocinaeError, QuestionSpecError) as exc:
        output.fail(str(exc))
    _print_choice_result(ctx, body, "tool", names, "tool")
    raise SystemExit(output.EXIT_OK)

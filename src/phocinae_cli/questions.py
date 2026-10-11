"""questions.py —— 题目 DSL 解析与校验。

命令行紧凑语法（可与 --questions-json 混用）：
  --noul   ok[:0.65]           noul 题（可选 threshold ∈ [0,1]，默认 0.5）
  --choice act:allow,ask,deny  choice 题（逗号分隔选项）
  --score  risk                score 题（答案 2–10）

协议约束（与 phocinae-server 一致）：
  id 非空且唯一；1–64 题；choice 必带 1–255 个非空选项；score 禁带 options；
  noul 的 threshold 仅在 [0,1]。
"""

import json

from .client import MAX_OPTIONS, MAX_QUESTIONS, PhocinaeError

VALID_TYPES = ("noul", "choice", "score")


class QuestionSpecError(PhocinaeError):
    """题目参数错误（用法错误，exit 1）。"""


def _split_options(text):
    parts = [p.strip() for p in text.split(",")]
    parts = [p for p in parts if p]
    return parts


def parse_specs(noul_specs=None, choice_specs=None, score_specs=None,
                questions_json=None):
    """把命令行题目参数合并为 /v1/systemone 的 questions 列表。

    noul_specs    : ["id", "id:0.65", ...]
    choice_specs  : ["id:opt1,opt2", ...]
    score_specs   : ["id", ...]
    questions_json: 内联 JSON 数组 / JSON 文件路径（完整规格，逐个校验）
    """
    questions = []

    for spec in (noul_specs or []):
        qid, _, thr = spec.partition(":")
        qid = qid.strip()
        if not qid:
            raise QuestionSpecError("--noul 语法：ID[:threshold]，得到 %r" % spec)
        q = {"id": qid, "type": "noul"}
        if thr.strip():
            try:
                t = float(thr)
            except ValueError:
                raise QuestionSpecError("--noul %s 的 threshold 不是数字" % spec)
            if not 0.0 <= t <= 1.0:
                raise QuestionSpecError("--noul %s 的 threshold 须在 [0,1]" % spec)
            q["threshold"] = t
        questions.append(q)

    for spec in (choice_specs or []):
        qid, sep, opts = spec.partition(":")
        qid = qid.strip()
        if not sep or not qid:
            raise QuestionSpecError("--choice 语法：ID:选项1,选项2，得到 %r" % spec)
        options = _split_options(opts)
        if not options:
            raise QuestionSpecError("--choice %s 没有选项" % spec)
        questions.append({"id": qid, "type": "choice", "options": options})

    for spec in (score_specs or []):
        qid = spec.strip()
        if not qid:
            raise QuestionSpecError("--score 语法：ID，得到 %r" % spec)
        questions.append({"id": qid, "type": "score"})

    if questions_json:
        raw = questions_json
        if raw.strip().startswith("[") or raw.strip().startswith("{"):
            data = raw
        else:  # 文件路径
            try:
                with open(raw, "r", encoding="utf-8") as fh:
                    data = fh.read()
            except OSError as exc:
                raise QuestionSpecError("无法读取 --questions-json 文件 %s：%s"
                                        % (raw, exc))
        try:
            extra = json.loads(data)
        except ValueError as exc:
            raise QuestionSpecError("--questions-json 不是合法 JSON：%s" % exc)
        if not isinstance(extra, list):
            raise QuestionSpecError("--questions-json 必须是 JSON 数组")
        questions.extend(extra)

    validate(questions)
    return questions


def validate(questions):
    """按 phocinae-server 协议校验 questions 列表（422 口径前置）。"""
    if not questions:
        raise QuestionSpecError(
            "至少需要一题：--noul / --choice / --score / --questions-json")
    if len(questions) > MAX_QUESTIONS:
        raise QuestionSpecError("题目数 %d 超过上限 %d" % (len(questions), MAX_QUESTIONS))
    seen = set()
    for q in questions:
        if not isinstance(q, dict):
            raise QuestionSpecError("题目必须是 JSON 对象，得到 %r" % (q,))
        qid = q.get("id")
        qtype = q.get("type")
        if not isinstance(qid, str) or not qid:
            raise QuestionSpecError("题目 id 必须是非空字符串")
        if qid in seen:
            raise QuestionSpecError("题目 id 重复：%r" % qid)
        seen.add(qid)
        if qtype not in VALID_TYPES:
            raise QuestionSpecError("题目 %r 的 type 必须是 noul/choice/score，"
                                    "得到 %r" % (qid, qtype))
        if qtype == "choice":
            opts = q.get("options")
            if not isinstance(opts, list) or not opts:
                raise QuestionSpecError("choice 题 %r 必须带非空 options" % qid)
            if len(opts) > MAX_OPTIONS:
                raise QuestionSpecError("choice 题 %r 选项数 %d 超过上限 %d"
                                        % (qid, len(opts), MAX_OPTIONS))
            if any(not isinstance(o, str) or not o for o in opts):
                raise QuestionSpecError("choice 题 %r 的选项必须是非空字符串" % qid)
        if qtype == "score" and q.get("options") is not None:
            raise QuestionSpecError("score 题 %r 不允许带 options" % qid)
        if qtype == "noul":
            thr = q.get("threshold")
            if thr is not None:
                try:
                    t = float(thr)
                except (TypeError, ValueError):
                    raise QuestionSpecError("noul 题 %r 的 threshold 不是数字" % qid)
                if not 0.0 <= t <= 1.0:
                    raise QuestionSpecError("noul 题 %r 的 threshold 须在 [0,1]"
                                            % qid)
    return questions

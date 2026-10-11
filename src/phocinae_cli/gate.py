"""gate.py —— 命令审批门编排：L0 离线判定 →（--l1 时）L1 模型两问 → fail-closed。

判定流程（与 phocinae-guard 同口径）：
  L0   纯离线确定性表（白名单 + 前缀 + 黑名单正则）→ allow / deny；
  L1   L0 不能定夺且 --l1 显式启用 → POST /v1/systemone 两问
       （noul 放行概率 + score 风险 2–10）→ 阈值映射 deny / ask / allow；
  fail-closed  服务器不可用 → 除白名单外一律 --fail-closed（deny/ask）。

退出码约定（本 CLI 全命令统一）：
  0 = allow（成功）   2 = deny   3 = ask（需人工确认）   1 = 错误
  注：与 phocinae-guard（deny=1/ask=2）不同——本任务口径规定 deny=2。
"""

import json

from . import __version__
from .client import (ResponseShapeError, noul_to_probability, unwrap_noul,
                     unwrap_score)
from .l0 import l0_judge

EXIT_ALLOW = 0
EXIT_DENY = 2
EXIT_ASK = 3
EXIT_ERROR = 1

# 与 phocinae-guard / phocinae-mcp 一致的通道阈值
NOUL_THRESHOLD = 0.65
DENY_AT = 7.0
ASK_AT = 4.0
GATE_TIMEOUT = 2.0


def map_l1(noul_p, score, noul_threshold=NOUL_THRESHOLD,
           deny_at=DENY_AT, ask_at=ASK_AT):
    """阈值映射（通道合成取最严格）：score>=deny_at 或 noul=false → deny；
    score>=ask_at 或 noul 摇摆 → ask；其余 → allow。"""
    if noul_p <= 1.0 - noul_threshold:
        noul_state = "false"
    elif noul_p >= noul_threshold:
        noul_state = "true"
    else:
        noul_state = "wavering"
    channels = []
    if score >= deny_at:
        channels.append("deny")
    elif score >= ask_at:
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


def l1_ask(client, command, cwd):
    """/v1/systemone 两问（与 guard 同题面）→ (noul_p, score)。"""
    state = json.dumps({"command": command, "cwd": cwd,
                        "tool": "phocinae-cli/" + __version__},
                       ensure_ascii=False)
    questions = [
        {"id": "guard_noul", "type": "noul",
         "instructions": "This command requires human review.",
         "criteria": {
             "false": "The command is safe to run without human attention.",
             "true": "A human should inspect this command before it runs."},
         "threshold": NOUL_THRESHOLD},
        {"id": "guard_score", "type": "score",
         "instructions": "Assess the risk of the command described in the state."},
    ]
    body = client.systemone(state, questions, perm=False)
    answers = body.get("answers", {})
    noul_raw = unwrap_noul(answers.get("guard_noul"))
    score_raw = unwrap_score(answers.get("guard_score"))
    if noul_raw is None or score_raw is None:
        raise ResponseShapeError("服务应答缺少 guard_noul / guard_score")
    return noul_to_probability(noul_raw), float(score_raw)


def decide(command, cwd, cfg):
    """gate 主判定：返回结果 dict（decision/layer/reason/noul/score/...）。"""
    result = {
        "command": command,
        "cwd": cwd,
        "decision": None,
        "layer": "L0",
        "reason": "",
        "noul": None,
        "score": None,
        "noul_state": None,
        "thresholds": {
            "noul_threshold": cfg["noul_threshold"],
            "deny_at": cfg["deny_at"],
            "ask_at": cfg["ask_at"],
        },
        "confirm": False,
    }
    decision, reason = l0_judge(command, cfg["table"])
    if decision is not None:
        result["decision"] = decision
        result["reason"] = reason
        return result
    # L0 不能定夺 → 灰区
    if not cfg["l1_enabled"]:
        result["decision"] = cfg["fail_closed"]
        result["layer"] = "fail_closed"
        result["reason"] = ("L1 未启用（--l1 才把灰区交给模型；"
                            "150M 权重未做过命令审批域校准）→ fail-closed=%s"
                            % cfg["fail_closed"])
        return result
    try:
        noul_p, score = l1_ask(cfg["client"], command, cwd)
    except Exception as exc:  # 网络/协议/结构异常 → fail-closed（绝不误放行）
        result["decision"] = cfg["fail_closed"]
        result["layer"] = "fail_closed"
        result["reason"] = ("L1 服务不可用或响应异常（%s: %s）→ fail-closed=%s"
                            % (type(exc).__name__, exc, cfg["fail_closed"]))
        return result
    decision, noul_state = map_l1(noul_p, score, cfg["noul_threshold"],
                                  cfg["deny_at"], cfg["ask_at"])
    result.update({
        "decision": decision,
        "layer": "L1",
        "reason": ("L1 noul=%.4f（%s，threshold=%.2f） score=%.4f"
                   "（deny>=%g，ask>=%g）→ %s"
                   % (noul_p, noul_state, cfg["noul_threshold"], score,
                      cfg["deny_at"], cfg["ask_at"], decision)),
        "noul": noul_p,
        "score": score,
        "noul_state": noul_state,
    })
    return result


def apply_confirm(result, confirm):
    """--confirm 人工确认：仅把 ask 升级为 allow；deny 不可覆盖。"""
    if not confirm:
        return result
    result["confirm"] = True
    if result["decision"] == "ask":
        result["decision"] = "allow"
        result["layer"] = "human_confirm"
        result["reason"] += "；--confirm 人工确认放行"
    elif result["decision"] == "deny":
        result["reason"] += "（--confirm 不能覆盖 deny）"
    return result


EXIT_CODES = {"allow": EXIT_ALLOW, "deny": EXIT_DENY, "ask": EXIT_ASK}

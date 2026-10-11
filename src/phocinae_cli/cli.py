"""cli.py —— phocinae CLI 主程序（typer）。

子命令：decide / classify / route / score / gate / ping。
全局选项：--server（env PHOC_SERVER）、--timeout、--retries、--model、
--json、--verbose。
"""

import os
import sys
from dataclasses import dataclass

import typer

from . import DEFAULT_MODEL, DEFAULT_SERVER, __version__
from .client import CONNECT_TIMEOUT, DEFAULT_RETRIES, DEFAULT_TIMEOUT, Client
from .output import EXIT_ERROR, EXIT_OK, console, kv_table, print_json

app = typer.Typer(
    name="phocinae",
    help="斑海豹 phocinae CLI —— 一行命令本地决策（/v1/systemone 客户端）。",
    add_completion=False,
    no_args_is_help=True,
)


@dataclass
class Ctx:
    """全局配置（typer callback 注入 ctx.obj）。"""
    server: str = DEFAULT_SERVER
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    model: str = DEFAULT_MODEL
    json: bool = False
    verbose: bool = False

    def client(self, timeout=None):
        return Client(server=self.server, timeout=timeout or self.timeout,
                      retries=self.retries, model=self.model,
                      verbosity=1 if self.verbose else 0)


@app.callback()
def _main(
    ctx: typer.Context,
    server: str = typer.Option(
        os.environ.get("PHOC_SERVER", DEFAULT_SERVER),
        "--server", help="phocinae-server 基地址（env PHOC_SERVER）"),
    timeout: float = typer.Option(
        DEFAULT_TIMEOUT, "--timeout", help="总请求超时秒数（默认 30）"),
    retries: int = typer.Option(
        DEFAULT_RETRIES, "--retries", help="连接错误/5xx 重试次数（默认 3）"),
    model: str = typer.Option(
        DEFAULT_MODEL, "--model", help="模型名（默认 Phocinae-Largha-150M-v1）"),
    json_: bool = typer.Option(
        False, "--json", help="输出原始 JSON（默认富表格）"),
    verbose: bool = typer.Option(
        False, "--verbose", help="显示重试与完整选项概率"),
    version_flag: bool = typer.Option(
        False, "--version", help="打印版本并退出"),
):
    if version_flag:
        console.print("phocinae CLI %s" % __version__)
        raise SystemExit(EXIT_OK)
    ctx.obj = Ctx(server=server, timeout=timeout, retries=retries,
                  model=model, json=json_, verbose=verbose)


@app.command()
def ping(ctx: typer.Context):
    """健康检查：GET /health + GET /v1/models。成功 exit 0，失败 exit 1。"""
    c = ctx.obj.client()
    try:
        health = c.health()
        models = c.models()
    except Exception as exc:
        sys.stderr.write("phocinae: 错误：%s\n" % exc)
        raise SystemExit(EXIT_ERROR)
    if ctx.obj.json:
        print_json({"health": health, "models": models})
        raise SystemExit(EXIT_OK)
    data = (models.get("data") or [{}])[0]
    kv_table([
        ("endpoint", c.server),
        ("status", health.get("status")),
        ("model", health.get("model")),
        ("model_loaded", health.get("model_loaded")),
        ("device", health.get("device")),
        ("uptime_s", health.get("uptime_s")),
        ("context_length", data.get("context_length")),
        ("perm_avg", data.get("perm_avg")),
        ("extensions", ", ".join(data.get("extensions") or [])),
    ], title="phocinae-server 健康检查")
    raise SystemExit(EXIT_OK)


# 子命令注册（函数定义于各模块，直接挂到主 app：phocinae decide ...）
from . import classify_route, decide, score_gate_cli  # noqa: E402

app.command("decide",
            help="state + questions → answers（表格式/JSON；管道与批量模式）")(
    decide.decide)
app.command("classify",
            help="state + labels → 单选标签（choice 题）")(
    classify_route.classify)
app.command("route",
            help="state + 工具列表 → 工具选择（4 排列平均 + escalate）")(
    classify_route.route)
app.command("score",
            help="state + criteria → 2–10 风险分（含各档概率）")(
    score_gate_cli.score)
app.command("gate",
            help="命令审批门：allow / deny / ask（L0 离线 + 可选 L1 + fail-closed）")(
    score_gate_cli.gate)


def main():
    # typer 的 no_args_is_help 在无子命令时会跳过 callback → 预先处理 --version
    if "--version" in sys.argv[1:]:
        console.print("phocinae CLI %s" % __version__)
        raise SystemExit(EXIT_OK)
    app()

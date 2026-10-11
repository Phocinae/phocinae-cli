#!/usr/bin/env bash
# run_smoke.sh —— phocinae CLI 冒烟测试（对 mock HTTP server）。
# 用法：bash tests/run_smoke.sh [--output tests/smoke_output.txt]
# 覆盖：6 个子命令、管道/批量、--json/表格、perm、422、服务未启动提示、
#       gate L0/L1/fail-closed 退出码、单文件零依赖版。
# 说明：gate L1 用例后缀（#xN）用 tests/mock_server.py 的 find_gate_case
#       按本脚本运行目录确定性搜索得到，mock 答案由 md5 播种 → 结果稳定。
set -u
set -o pipefail   # 管道退出码取最右非零：echo exit=$? 才能反映 CLI 真实退出码

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
VENV_PY="${VENV_PY:-/home/hermes/decision-model/.venv/bin/python}"
PHOC="${PHOC:-/home/hermes/decision-model/.venv/bin/phocinae}"
MOCK_PORT=18155
DEAD_PORT=18156
export PHOC_SERVER="http://127.0.0.1:${MOCK_PORT}"

# gate L1 确定性用例（cwd 必须等于本脚本运行目录，即包根目录）
GATE_ALLOW='git push origin main #x5'
GATE_ASK='git push origin main #x1'
GATE_DENY='git push origin main #x0'

echo "==================================================================="
echo " phocinae CLI v0.1.0 冒烟测试"
echo " 时间: $(date '+%F %T')  运行目录: $HERE"
echo " mock: http://127.0.0.1:${MOCK_PORT}  死端口: ${DEAD_PORT}（错误路径）"
echo "==================================================================="

# ---------------------------------------------------------------- 0. 安装
echo ""
echo "########## 0. 安装（pip install -e .）##########"
"$VENV_PY" -m pip show phocinae-cli 2>/dev/null | sed -n '1,4p'
"$PHOC" --version
echo "exit=$?"

# ---------------------------------------------------------------- mock
echo ""
echo "########## 1. 启动 mock server ##########"
"$VENV_PY" tests/mock_server.py --port "$MOCK_PORT" &
MOCK_PID=$!
trap 'kill "$MOCK_PID" 2>/dev/null' EXIT
for i in $(seq 1 50); do
    if curl -s -m 1 "http://127.0.0.1:${MOCK_PORT}/health" > /dev/null 2>&1; then
        echo "mock 已就绪（pid=$MOCK_PID，尝试 $i 次）"
        break
    fi
    sleep 0.1
done

# ---------------------------------------------------------------- 2. ping
echo ""
echo "########## 2. ping 健康检查 ##########"
"$PHOC" ping
echo "exit=$?"
"$PHOC" --json ping
echo "exit=$?"
echo "--- 死端口（应 exit 1 + 可行动提示）："
"$PHOC" --server "http://127.0.0.1:${DEAD_PORT}" ping 2>&1 | tail -6
echo "exit=$?"

# ---------------------------------------------------------------- 3. decide
echo ""
echo "########## 3. decide：state + questions → answers ##########"
"$PHOC" decide --state "The agent restarted nginx after checking the logs and the health endpoint is green." \
    --noul ok:0.65 --choice act:allow,ask,deny --score risk
echo "exit=$?"
echo "--- --json 输出："
"$PHOC" --json decide --state "json mode demo" --noul ok
echo "exit=$?"
echo "--- --perm（4 排列平均）："
"$PHOC" decide --state "perm demo" --choice act:alpha,beta,gamma --perm
echo "exit=$?"
echo "--- --questions-json 完整规格："
"$PHOC" decide --state "questions-json demo" \
    --questions-json '[{"id":"q1","type":"noul"},{"id":"q2","type":"score"}]'
echo "exit=$?"
echo "--- 管道模式（stdin → state）："
echo "The service is down and users are reporting errors." \
    | "$PHOC" decide --noul ok --choice act:allow,ask,deny
echo "exit=$?"
echo "--- 批量模式（stdin 每行一条 state，经 /v1/systemone/batch）："
printf 'state alpha one\nstate beta two\n{"state": "json line state"}\n' \
    | "$PHOC" decide --batch --noul ok --choice act:x,y
echo "exit=$?"

# ---------------------------------------------------------------- 4. classify
echo ""
echo "########## 4. classify：state + labels → 单选 ##########"
"$PHOC" classify --state "Customer says the account was hacked and asks for a refund." \
    --labels allow,ask,deny
echo "exit=$?"
echo "--- 管道模式："
echo "The disk usage is at 97% and the backup job will start soon." \
    | "$PHOC" classify --labels allow,ask,deny
echo "exit=$?"

# ---------------------------------------------------------------- 5. route
echo ""
echo "########## 5. route：state + 工具列表 → 工具选择 ##########"
"$PHOC" route --state "User asks for the current weather in Paris." \
    --tools "web_search:搜索公开网络,read_file:读取本地文件,python_exec:执行 Python 代码"
echo "exit=$?"
echo "--- 超过 10 个工具（应报错 exit 1）："
"$PHOC" route --state "x" --tools a,b,c,d,e,f,g,h,i,j,k
echo "exit=$?"

# ---------------------------------------------------------------- 6. score
echo ""
echo "########## 6. score：state + criteria → 2–10 分 ##########"
"$PHOC" score --state "The agent will delete production database tables." \
    --criteria "评估该操作的破坏性风险"
echo "exit=$?"
echo "--- 管道模式："
echo "The agent will read a public README file." | "$PHOC" score
echo "exit=$?"

# ---------------------------------------------------------------- 7. gate
echo ""
echo "########## 7. gate：命令审批门 ##########"
echo "--- L0 白名单（exit 0）："
"$PHOC" gate --command "git status"
echo "exit=$?"
echo "--- L0 黑名单（exit 2）："
"$PHOC" gate --command "rm -rf /"
echo "exit=$?"
echo "--- stdin + --json（deny，exit 2）："
echo "sudo rm -rf /etc" | "$PHOC" gate --json
echo "exit=$?"
echo "--- L0 前缀白名单（exit 0）："
"$PHOC" gate --command "git diff HEAD~1"
echo "exit=$?"
echo "--- 灰区默认 fail-closed deny（无 --l1，exit 2）："
"$PHOC" gate --command "pip install requests"
echo "exit=$?"
echo "--- L1 allow（mock 确定性用例，exit 0）："
"$PHOC" gate --l1 --command "$GATE_ALLOW"
echo "exit=$?"
echo "--- L1 ask（exit 3）："
"$PHOC" gate --l1 --command "$GATE_ASK"
echo "exit=$?"
echo "--- L1 deny（exit 2）："
"$PHOC" gate --l1 --command "$GATE_DENY"
echo "exit=$?"
echo "--- --confirm 把 ask 升级 allow（exit 0）："
"$PHOC" gate --l1 --confirm --command "$GATE_ASK"
echo "exit=$?"
echo "--- 服务不可用 fail-closed deny（exit 2）："
"$PHOC" --server "http://127.0.0.1:${DEAD_PORT}" gate --l1 --command "pip install requests" 2>&1 | tail -3
echo "exit=$?"
echo "--- 服务不可用 fail-closed ask（exit 3）："
"$PHOC" --server "http://127.0.0.1:${DEAD_PORT}" gate --l1 --fail-closed ask --command "pip install requests" 2>&1 | tail -3
echo "exit=$?"

# ---------------------------------------------------------------- 8. 错误路径
echo ""
echo "########## 8. 错误分类与提示 ##########"
echo "--- 服务未启动（decide，exit 1 + 可行动提示）："
"$PHOC" --server "http://127.0.0.1:${DEAD_PORT}" decide --state "x" --noul ok
echo "exit=$?"
echo "--- 服务端 422（模型名错误，exit 1）："
"$PHOC" --model WrongModel decide --state "x" --noul ok
echo "exit=$?"
echo "--- 用法错误：题目 id 重复（exit 1）："
"$PHOC" decide --state "x" --choice bad:a,b --choice bad:c,d
echo "exit=$?"
echo "--- 用法错误：--batch 与 --state 互斥（exit 1）："
echo "x" | "$PHOC" decide --batch --state "y" --noul ok
echo "exit=$?"

# ---------------------------------------------------------------- 9. 单文件版
echo ""
echo "########## 9. 单文件零依赖版 phocinae.py（argparse+urllib）##########"
"$VENV_PY" phocinae.py --version
echo "exit=$?"
"$VENV_PY" phocinae.py ping
echo "exit=$?"
"$VENV_PY" phocinae.py decide --state "single-file demo" --noul ok --choice act:allow,deny --score risk
echo "exit=$?"
echo "--- 管道模式："
echo "piped state" | "$VENV_PY" phocinae.py decide --noul ok
echo "exit=$?"
echo "--- gate L0 allow（exit 0）："
"$VENV_PY" phocinae.py gate --command "git status"
echo "exit=$?"
echo "--- gate L0 deny（exit 2）："
"$VENV_PY" phocinae.py gate --command "rm -rf /"
echo "exit=$?"
echo "--- gate 灰区默认 fail-closed（exit 2）："
"$VENV_PY" phocinae.py gate --command "pip install requests"
echo "exit=$?"
echo "--- 死端口提示（exit 1）："
"$VENV_PY" phocinae.py --server "http://127.0.0.1:${DEAD_PORT}" ping 2>&1 | tail -5
echo "exit=$?"

echo ""
echo "==================================================================="
echo " 冒烟测试完成（mock pid=$MOCK_PID 将被清理）"
echo "==================================================================="

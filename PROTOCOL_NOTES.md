# phocinae-server 协议要点（开发探明记录）

来源：`/home/hermes/dev/phocinae-largha-150m/docs/protocol.md` +
`/home/hermes/dev/phocinae-server/phocinae/server.py` / `engine.py` 源码
（server 0.1.3，本机 8155 当时未运行 → 冒烟用 tests/mock_server.py 对齐形状）。

## 端点

| method | path | 说明 |
|---|---|---|
| GET | `/` | 服务信息（service/model/docs/health） |
| GET | `/health` | 存活 + model/device/uptime_s（无鉴权） |
| GET | `/v1/models` | 模型目录（context_length、answer_formats、extensions、perm_avg） |
| POST | `/v1/systemone` | 单次决策 |
| POST | `/v1/systemone/permute` | 同左，choice 题 4 排列平均 |
| POST | `/v1/systemone/batch` | ≤64 条批量（数组或 `{"requests": [...]}`） |

## 请求/响应形状

request：`{model, state, questions[]}`；question：`{id, type, options?, threshold?}`
（extra keys 如 instructions/criteria 被 pydantic 忽略、供提示渲染用）。
response：`{model, answers{}, usage{}, answer_confidence{}, action{},
option_scores{}, routing{}}`。

- answers：noul→bool；choice→**0 基**选项下标 int；score→int 2–10
- answer_confidence：温度标定 top 概率（4dp）；action：{qid: {act_probability}}
- option_scores：标定概率向量（choice 请求顺序；noul [p(false),p(true)]；
  score 档 2–10 九维）；`PHOC_EXTENSIONS=0` 可关扩展键（gate/route 依赖它们）
- routing：device（cpu/cuda）、perm（none/avg-k4）、backend

## 约束（422）

model 名须精确 `Phocinae-Largha-150M-v1`（大小写敏感）；questions 1–64；
id 非空唯一；choice 必带 1–255 选项；score 禁带 options；noul threshold∈[0,1]
（默认 0.5）；batch 空/超 64 → 422；body>2MiB → 413 `{"error":{code,message}}`；
`PHOC_BEARER_TOKEN` 设置时需 Bearer 头否则 401。

## 生态口径（本 CLI 遵循）

- **工具路由**（phocinae-router 冻结口径）：菜单 ≤10（JevBench tool_selection
  域界）、`name: desc` 渲染（banking77 先例）、4 排列平均压顺序翻转
  （`/permute` 或 `PHOC_PERM_AVG=1`，4× 前向）。
- **E1 升级门**：τ=0.6（保留集 acc 0.886、省费 54.4%）；confidence<τ → escalate。
- **命令审批门**（phocinae-guard 同口径）：noul 阈值 0.65（≥0.65 放行、
  ≤0.35 拒绝、中间摇摆）、score deny≥7 / ask≥4，通道合成取最严；
  **P0 口径：150M 权重未做过命令审批域校准（L1 信号≈噪声），guard 默认
  L1 关、fail-closed**；L0 表（白名单精确/前缀/黑名单正则）纯离线。
- 确定性：同请求同设备同 batch 形状 → 位级一致；fp16/fp32 末位可差。
- 应答兼容：guard/mcp 家族接受「扁平值」与「旧 mock 嵌套对象」两种 answers
  形状（`_unwrap` 同口径），本 CLI 的 unwrap_noul/choice/score 保持一致。

## 本 CLI 的偏差（有意）

- 退出码：allow=0 / 错误=1 / deny=2 / ask=3（guard 为 deny=1/ask=2——
  本任务口径规定 deny=2）。
- gate L1 默认关（--l1 启用），fail-closed 默认 deny（可 --fail-closed ask）。
- 客户端前置校验题目规格（422 口径），坏请求不打扰服务。

# client2gui 五轴注意力融合设置接入

## 交付范围与前提

Core PR #38 提供五轴融合算法，CLI PR #194 提供环境变量映射。本次扩展提供持久设置、TUI 编辑入口和配置回执。client2gui 本身尚未修改，本文说明如何接入。

GUI 只编辑设置和显示宿主回执。算法仍在 Core 内执行。GUI 不计算 softmax、候选库大小门控或最终排名。

配套 SDK 必须声明 `recall_fusion_contract: 1`。CLI 构建会检查该能力，防止旧 SDK 静默忽略设置。部署时应使用包含本次设置扩展的 CLI dev 包；Apple 推理修复 dev 先发布，再发布包含五轴设置的新 dev。最终版本以发布回执为准。

## 界面位置与行为

在现有“推理设置”页面增加“五轴注意力融合”区域。当前 client2 源码对应 `internal/desktop/frontend/pages/models.js`。

- 首行显示“当前生效模式”。编辑区显示“已保存设置”。两者可能因环境覆盖而不同。
- 模式使用下拉框。八个数值参数放入“高级参数”，默认折叠。
- 提供“保存”和“恢复默认”按钮。“恢复默认”只修改草稿，用户保存后才生效。
- 进入页面时读取配置。保存后回读配置，成功后更新界面。
- 未保存就离开页面时，不写入 Runtime。保存期间禁用重复提交。
- 若回执没有 `recall_fusion_runtime.effective`，禁用保存并提示升级 CLI。不要只根据版本号猜测能力。

TUI 对应入口为“模型 / 推理设置 → 五轴注意力融合设置”。Tab 或上下键切换字段；模式可用左右键选择；Ctrl+A 全选；Ctrl+S 保存；Esc 返回。表单保存会回读，环境覆盖字段保持可见。

## 模式

| 值 | 建议显示名 | 行为 |
| --- | --- | --- |
| `legacy` | 原有融合（默认） | 保持原有加权排名。安装或升级不会自动启用注意力融合。 |
| `attention` | 五轴注意力融合 | 对已通过准入检查的向量候选，融合语义、词法、时间、热度和树位置。 |
| `attention_anchor` | 相关性锚定融合 | 保留原有语义与词法相关性组合，对先验信号使用注意力。 |
| `auto` | 自动选择 | Core 按授权候选库大小选择；当前拟合边界约为 376 条，小库使用注意力，大库使用原算法。 |

`auto` 的边界来自现有评测，不能说明所有真实库都能提高召回质量。GUI 不承诺质量提升，也不复制这个阈值作为自己的逻辑。

## 字段、默认值与校验

持久设置使用单个 `agent.json` 键 `recall_fusion`，值为 JSON 对象。对象内部使用 Core 字段名。

| 字段 | 建议显示名 | 默认值 | 有效范围 |
| --- | --- | --- | --- |
| `fusion` | 融合模式 | `legacy` | 上表四种模式 |
| `fusion_alpha` | 先验总份额 | 0.20 | 0–1 |
| `fusion_beta` | 词法份额 | 0.25 | 0–1 |
| `fusion_temperature` | 注意力温度 | 1.0 | 大于 0，且不大于 10 |
| `fusion_gate_recency` | 普通查询时间门 | 0.02 | 0–1 |
| `fusion_gate_recency_temporal` | 时间查询时间门 | 1.0 | 0–1 |
| `fusion_gate_hot` | 热度门 | 0.10 | 0–1 |
| `fusion_gate_tree` | 树位置门 | 0.02 | 0–1 |
| `fusion_temporal_alpha` | 时间查询追加份额 | 0.15 | 0–1 |

数值必须是有限 JSON number，不能是字符串、空值、NaN 或 Infinity。还必须满足 `fusion_alpha + fusion_beta <= 1`。宿主和 Core 都会校验，前端校验只用于即时提示。未知字段会被宿主拒绝。

这不是五个任意权重输入框。语义保留剩余份额；时间、热度和树位置在先验份额内由各自门值参与。时间查询会增加先验份额，并受剩余可用份额限制。无向量候选和消融设置仍遵循 Core 的既有规则。

## 复用现有 RPC

client2 的 `internal/host/commands_settings.go` 已提供以下命令映射，因此无需新增 Go 命令，也无需写 agent.json 文件。

| GUI 命令 | 参数 | CLI 命令 |
| --- | --- | --- |
| `agent_config` | 无 | `agent-config` |
| `agent_set` | `{ setting: string }` | `agent-config --set <setting>` |

使用 `internal/desktop/frontend/ui/core.js` 现有的 `execute` 和 `summary`，保持现有任务处理和错误提示。

读取示例：

```js
const envelope = await execute("agent_config");
const state = summary(envelope).recall_fusion_runtime;
if (!state || !state.effective) {
  throw new Error("请先升级支持五轴融合设置的 CLI");
}
const draft = { ...state.defaults, ...state.configured };
```

回执示例（位于 `agent-config` 的 `summary.recall_fusion_runtime`）：

```json
{
  "configured": { "fusion": "auto" },
  "effective": {
    "fusion": "auto",
    "fusion_alpha": 0.2,
    "fusion_beta": 0.25,
    "fusion_temperature": 1.0,
    "fusion_gate_recency": 0.02,
    "fusion_gate_recency_temporal": 1.0,
    "fusion_gate_hot": 0.1,
    "fusion_gate_tree": 0.02,
    "fusion_temporal_alpha": 0.15
  },
  "defaults": {
    "fusion": "legacy",
    "fusion_alpha": 0.2,
    "fusion_beta": 0.25,
    "fusion_temperature": 1.0,
    "fusion_gate_recency": 0.02,
    "fusion_gate_recency_temporal": 1.0,
    "fusion_gate_hot": 0.1,
    "fusion_gate_tree": 0.02,
    "fusion_temporal_alpha": 0.15
  },
  "overrides": [],
  "applies": "next_query"
}
```

`configured` 是已保存的部分或完整对象。`defaults` 补全未设置字段。`effective` 是 Runtime 下一次请求会使用的设置，不代表某条查询最终选择的算法。例如 `effective.fusion=auto` 表示启用自动选择，不是固定选择 attention。

保存整个对象，不能逐字段写入顶层键：

```js
// 在此之前检查原始输入非空，再把八个数值字段转换为有限 number。
await execute("agent_set", {
  setting: "recall_fusion=" + JSON.stringify(draft),
});
const readBack = summary(await execute("agent_config")).recall_fusion_runtime;
if (!readBack?.configured ||
    Object.keys(draft).some(key => readBack.configured[key] !== draft[key])) {
  throw new Error("保存后的回读不一致，请刷新设置");
}
// 比较通过后显示已保存，并显示 readBack.effective / overrides。
```

不要把 JSON 拼成 shell 命令。`setting` 是结构化参数中的一个字符串，现有命令层会将它作为单个 argv 传给 CLI。

清除持久覆盖可保存空对象：`setting: "recall_fusion={}"`。清除后使用默认值及环境变量。若“恢复默认”需要明确保存全部默认值，则保存 `state.defaults`；二者都不会清除 Runtime 的环境变量。

## 优先级与生效时间

优先级从高到低为：Runtime 环境变量（包括旧别名）→ 已保存的 `recall_fusion` → 默认值。`RSRS_RECALL_PROFILE=legacy` 会显式固定 `fusion=legacy`；单独的 `RSRS_RECALL_FUSION` 可再覆盖该模式。

| 环境变量 | 覆盖字段 |
| --- | --- |
| `RSRS_RECALL_FUSION` | `fusion` |
| `RSRS_RECALL_FUSION_ALPHA` | `fusion_alpha` |
| `RSRS_RECALL_FUSION_BETA` | `fusion_beta` |
| `RSRS_RECALL_FUSION_TEMPERATURE` | `fusion_temperature` |
| `RSRS_RECALL_FUSION_GATE_RECENCY` | `fusion_gate_recency` |
| `RSRS_RECALL_FUSION_GATE_RECENCY_TEMPORAL` | `fusion_gate_recency_temporal` |
| `RSRS_RECALL_FUSION_GATE_HOT` | `fusion_gate_hot` |
| `RSRS_RECALL_FUSION_GATE_TREE` | `fusion_gate_tree` |
| `RSRS_RECALL_FUSION_TEMPORAL_ALPHA` | `fusion_temporal_alpha` |

`overrides` 返回被环境覆盖的字段名。若数组非空，显示“已保存，但这些字段由 Runtime 环境覆盖”，并逐项显示生效值。不要显示“设置已启用”后隐藏覆盖情况。

宿主在每次召回前读取持久配置，无需重建索引、重载模型或重启 Runtime。已经开始的请求保留自己的设置快照。修改 Runtime 的环境变量通常需要重启该进程；修改 GUI 进程的环境不会改变已运行的 Runtime。

设置作用于当前数据目录下的 Runtime 配置，不是服务器共享偏好。切换数据目录后必须重新读取，不能复用旧草稿。

## 错误处理与验收

保存被拒绝时保留草稿，并显示宿主错误。写入成功但回读失败时，提示“结果待确认，请刷新”，不要自动重试写入。回读时若已保存对象与草稿不同，应提示配置发生变化。若配置相同而生效值不同，应解释环境覆盖。

接入 GUI 后按以下步骤验收：

1. 无持久设置时显示 legacy 和全部默认值。旧 CLI 不显示可用保存按钮。
2. 选择四种模式分别保存，关闭并重开页面后读取一致。
3. 拒绝空数字、字符串、越界值、零温度及 alpha + beta 大于 1；失败不修改已保存配置。
4. 修改参数后取消，确认持久配置不变。恢复默认只改草稿，保存后再回读。
5. 启动 Runtime 时设置一个环境覆盖；保存后显示 configured 与 effective 的区别及字段提示。
6. 同一 Runtime 中保存设置后执行下一次召回，确认请求采用新设置。无需重建模型索引。
7. 保存期间禁用重复提交；模拟回读失败后只刷新，不自动重写。
8. 切换数据目录后重新读取；验证小窗口、键盘导航、中英文文案和高级参数布局。

本文给出实现契约和验收要求，不代表 client2gui 已经实现或完成桌面交互验收。

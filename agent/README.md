# ReAct Agent 静态分析实验

## 任务说明

本项目对 `targets/challenge` 进行静态分析。目标程序为 Linux x86_64 stripped ELF。

Agent 采用 ReAct 风格的 Thought → Action → Observation 闭环，由规划器生成结构化 Action，并调用只读静态分析工具完成分析。

本实验不进行 exploit，不进行动态验证。

## 工具要求

需要安装并配置：

- radare2
- Ghidra Headless

### radare2

确认 `r2` 在 PATH 中：

```bash
which r2
r2 -v
```

如果 `r2` 不在 PATH 中，可以设置：

```bash
export R2_BIN=/path/to/r2
```

### Ghidra Headless

设置 Ghidra Headless 路径，例如：

```bash
export GHIDRA_HEADLESS="$HOME/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless"
```

验证：

```bash
"$GHIDRA_HEADLESS" -help | head
```

## 运行方式

进入 `agent/` 目录后执行：

```bash
python3 agent.py --target targets/challenge --log ../logs/run.txt --out ../vuln.json
```

## 输出文件

运行完成后生成：

```txt
../logs/run.txt
../vuln.json
```

其中：

- `logs/run.txt`：完整 ReAct 交互日志
- `vuln.json`：Agent Final Answer 的结构化漏洞结论

## 项目结构

```txt
vuln.json
logs/
  run.txt
agent/
  agent.py
  requirements.txt
  README.md
  scripts/
    DumpGhidraAnalysis.java
  targets/
    challenge
```

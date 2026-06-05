# 基于 ReAct 智能体与 angr 的自动化逆向分析实验

本工程实现了一个简化的 ReAct Agent：LLM/规划器负责推理、选择工具与组织观察，angr 负责符号执行和输入求解。

## 文件说明

- `crackme.c`：实验目标程序源码。
- `agent_react_angr.py`：ReAct 主程序，包含工具封装、Action 解析/派发、Observation 构造。
- `requirements.txt`：Python 依赖。
- `run_log.txt`：不少于 3 轮的 Thought → Action → Observation 运行日志。
- `report.md` / `report.docx`：实验报告。

## 环境安装

```bash
gcc crackme.c -O0 -g -no-pie -fno-stack-protector -o crackme
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

如在 Windows 上运行，建议使用 WSL/Ubuntu；如果 `-no-pie` 参数不可用，可先去掉，但报告中的地址会随环境变化。

## 运行方式

无 API Key 时使用脚本化规划器，仍会执行完整 ReAct 闭环：

```bash
python agent_react_angr.py --binary ./crackme --llm scripted --max-rounds 5
```

如需接入 OpenAI 工具调用式模型：

```bash
export OPENAI_API_KEY="你的 API Key"
python agent_react_angr.py --binary ./crackme --llm openai --model gpt-4o-mini
```

期望求解结果：`AZcE`。

## Git 提交示例

```bash
git init
git add .
git commit -m "complete react angr lab"
# git remote add origin <你的仓库地址>
# git push origin main
```

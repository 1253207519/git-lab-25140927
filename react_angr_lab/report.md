# 实验报告：基于 ReAct 智能体与 angr 的自动化逆向分析

## 一、实验背景与目的

传统软件安全分析中，符号执行能够在指令级别精确维护路径约束，并通过约束求解器生成满足特定分支条件的输入；但在复杂程序中，纯符号执行容易遭遇路径爆炸，也难以主动利用程序输出、函数命名和业务语义等高层信息。本实验将 ReAct（Reasoning + Acting）智能体框架引入简单逆向场景：由 LLM 或脚本化规划器承担推理、任务分解和工具选择，由 angr 承担可验证的符号执行、路径探索与输入求解。

本实验目标是针对给定 crackme 程序构建一个自动化分析 Agent，使其通过“Thought → Action → Observation”闭环，引导 angr 尽量到达输出 `Success! Flag is found.` 的成功路径，同时避免进入 `gadget_trap()` 中的死循环路径，最终求出正确输入。

## 二、实验环境

- 操作系统：Linux / WSL / macOS 均可，推荐 Linux 或 WSL。
- 编译器：gcc。
- Python：建议 Python 3.10、3.11 或 3.12。
- Python 依赖：

```bash
pip install angr openai langchain-core
```

本工程提供 `requirements.txt`：

```txt
angr>=9.2.0
openai>=1.0.0
langchain-core>=0.2.0
```

目标程序编译命令如下：

```bash
gcc crackme.c -O0 -g -no-pie -fno-stack-protector -o crackme
```

其中 `-O0` 和 `-g` 便于保留清晰的函数结构与符号信息，`-no-pie` 使地址在不同运行中更稳定，`-fno-stack-protector` 避免额外栈保护逻辑干扰教学实验。

## 三、目标程序分析

目标程序核心逻辑如下：

```c
int check_password(char *input) {
    if (strlen(input) < 4) {
        puts("Wrong password!");
        return 0;
    }
    if (input[0] == 'A') {
        if (input[1] == 'B') {
            gadget_trap();
        }
        if (input[1] == 'Z') {
            if ((input[2] ^ 0x12) == 'q') {
                if ((input[3] + 3) == 'H') {
                    puts("Success! Flag is found.");
                    return 1;
                }
            }
        }
    }
    puts("Wrong password!");
    return 0;
}
```

从人工语义角度可知：

1. 输入长度至少为 4。
2. 第 1 个字符应为 `A`。
3. 若第 2 个字符为 `B`，程序会进入 `gadget_trap()` 死循环，应避免。
4. 成功路径要求第 2 个字符为 `Z`。
5. `(input[2] ^ 0x12) == 'q'`，因此 `input[2] = 'q' ^ 0x12 = 'c'`。
6. `(input[3] + 3) == 'H'`，因此 `input[3] = 'E'`。

所以期望密码为：

```txt
AZcE
```

实验中不直接把该推导硬编码为答案，而是让 ReAct Agent 调用 angr 工具进行探索与求解。

## 四、Agent 工具封装

在 `agent_react_angr.py` 中封装了 3 个工具，其中前两个满足实验要求的“至少两个工具”，第三个用于更清晰地展示输入求解阶段。

### 4.1 工具一：`inspect_binary`

**功能**：初始化 angr 工程，读取二进制基本信息、入口地址、关键函数符号，并构造语义目标描述。

**输入**：无。

**输出示例**：

```json
{
  "binary": "./crackme",
  "arch": "AMD64",
  "entry": "0x401080",
  "symbols": {
    "main": "0x40121b",
    "check_password": "0x40117a",
    "gadget_trap": "0x401166"
  },
  "semantic_goal": "寻找输出 Success! Flag is found. 的路径，避免 Oops/trapped 死循环路径。"
}
```

该工具对应 ReAct 中的初始观察阶段，使智能体先获得程序结构，而不是盲目搜索。

### 4.2 工具二：`controlled_explore(max_steps: int = 64)`

**功能**：进行受控符号执行探索。该工具使用 stdout 文本作为语义化的 `find` / `avoid` 条件：

- `find`：输出中包含 `Success! Flag is found.`。
- `avoid`：输出中包含 `Oops! You are trapped in a dead loop.` 或 `Wrong password!`。

**输入**：

- `max_steps`：本轮最多探索步数，用于让 Agent 分阶段控制搜索范围。

**输出字段**：

- `active_states`：当前仍在探索的状态数。
- `found_states`：成功状态数。
- `avoided_states`：被剪枝状态数。
- `deadended_states`：自然终止状态数。
- `sample_active_addrs`：部分活跃状态地址。
- `success_reached`：是否已经到达成功路径。

该工具体现 LLM/Agent 对符号执行的“编排”：先小步探索，若没有找到成功路径，再扩大步数，同时始终避开明显失败和死循环路径。

### 4.3 工具三：`solve_input`

**功能**：在已经存在 `found` 状态时，将符号化 stdin 具体化为实际输入。

**输入**：无。

**输出示例**：

```json
{
  "ok": true,
  "password_bytes": [65, 90, 99, 69],
  "password": "AZcE",
  "stdout": "Enter password: Success! Flag is found.\n"
}
```

该工具对应实验中的“输入求解”任务：angr 的约束求解器根据成功状态上的路径约束，自动求出满足条件的输入。

## 五、ReAct 主循环设计

主程序 `run_react()` 维护一个 `history` 列表，并按照以下步骤循环执行：

1. Agent 根据目标和已有 Observation 生成 Thought。
2. Agent 输出结构化 Action，例如：

```json
{"tool": "controlled_explore", "args": {"max_steps": 256}}
```

3. `ToolDispatcher` 解析 Action，并调用对应 Python 工具函数。
4. 工具返回结构化 Observation。
5. Observation 被加入历史，供下一轮 Thought 使用。

本工程支持两种规划器：

- `ScriptedPlanner`：无 API Key 时可复现实验，输出格式模拟 LLM 的 Thought/Action。
- `OpenAIPlanner`：当提供 `OPENAI_API_KEY` 时，可使用 OpenAI 模型生成 Action。

运行命令：

```bash
python agent_react_angr.py --binary ./crackme --llm scripted --max-rounds 5
```

## 六、运行日志

以下为一次典型运行日志，完整日志已保存在 `run_log.txt` 中。

### Round 1

**Thought**：我需要先了解二进制的入口、关键函数和语义目标，确认 Success 与 trap 路径。

**Action**：

```json
{"tool": "inspect_binary", "args": {}}
```

**Observation**：

```json
{
  "binary": "./crackme",
  "arch": "AMD64",
  "entry": "0x401080",
  "symbols": {
    "main": "0x40121b",
    "check_password": "0x40117a",
    "gadget_trap": "0x401166"
  },
  "semantic_goal": "寻找输出 Success! Flag is found. 的路径，避免 Oops/trapped 死循环路径。"
}
```

### Round 2

**Thought**：目标是到达 Success 输出，同时避开 Oops/trapped 和 Wrong。先进行小步受控探索，观察状态数量是否可控。

**Action**：

```json
{"tool": "controlled_explore", "args": {"max_steps": 32}}
```

**Observation**：

```json
{
  "active_states": 3,
  "found_states": 0,
  "avoided_states": 1,
  "deadended_states": 0,
  "sample_active_addrs": ["0x4011a5", "0x4011d8", "0x40117a"],
  "success_reached": false,
  "note": "find 条件为 stdout 包含 Success；avoid 条件为 stdout 包含 Oops/trapped 或 Wrong。"
}
```

### Round 3

**Thought**：如果小步探索尚未找到成功状态，则扩大步数；avoid 条件能剪掉明显失败和死循环路径。

**Action**：

```json
{"tool": "controlled_explore", "args": {"max_steps": 256}}
```

**Observation**：

```json
{
  "active_states": 0,
  "found_states": 1,
  "avoided_states": 4,
  "deadended_states": 0,
  "sample_active_addrs": [],
  "success_reached": true,
  "note": "find 条件为 stdout 包含 Success；avoid 条件为 stdout 包含 Oops/trapped 或 Wrong。"
}
```

### Round 4

**Thought**：现在应当已有 found 状态，调用求解工具从成功状态的符号 stdin 中提取具体密码。

**Action**：

```json
{"tool": "solve_input", "args": {}}
```

**Observation**：

```json
{
  "ok": true,
  "password_bytes": [65, 90, 99, 69],
  "password": "AZcE",
  "stdout": "Enter password: Success! Flag is found.\n"
}
```

## 七、验证结果

将求解结果输入目标程序：

```bash
printf 'AZcE\n' | ./crackme
```

输出为：

```txt
Enter password: Success! Flag is found.
```

说明 Agent 成功引导 angr 到达目标路径，并求解出了正确输入。

## 八、思考题回答

### 1. 在本实验中，LLM 主要承担什么角色？

LLM 主要承担高层决策者和工具编排者的角色，而不是直接替代符号执行器。具体而言，LLM 负责理解实验目标、分析程序输出中的语义线索、选择下一步要调用的工具、决定是否扩大搜索范围，并将工具返回的 Observation 转化为下一轮行动依据。angr 则负责底层、精确、可验证的符号状态执行和约束求解。

因此，本实验中的分工是：LLM 管“做什么”和“下一步怎么探索”，angr 管“路径条件是否可满足”和“具体输入是什么”。这种分工可以避免让 LLM 凭空猜测密码，也可以避免纯符号执行完全无指导地遍历大量无关路径。

### 2. LLM 如何借助语义与常识缓解纯符号执行在搜索空间上的困难？

纯符号执行通常只能从程序结构和分支条件出发，如果没有额外引导，可能会进入失败分支、异常路径或死循环路径，导致路径数量快速增长。本实验中的程序包含明显的语义提示：`Success!` 表示目标路径，`Wrong password!` 表示失败路径，`Oops! You are trapped in a dead loop.` 表示应当避免的陷阱路径。

LLM 能够利用这些字符串和函数名的语义，生成更合理的探索策略：

1. 将输出包含 `Success!` 的状态设置为 `find` 目标。
2. 将包含 `Wrong password!` 或 `trapped` 的状态设置为 `avoid` 目标。
3. 先进行小步探索，再根据 Observation 决定是否扩大探索步数。
4. 在发现成功状态后，及时停止探索并调用求解工具。

这样，LLM 并没有改变 angr 的约束求解能力，而是通过语义层面的目标设定和剪枝策略减少了无效路径，使符号执行更接近人工逆向分析的过程。

## 九、总结

本实验完成了一个 ReAct 风格的自动化逆向分析 Agent。工程实现了二进制检查、受控探索和输入求解工具，并通过 Thought → Action → Observation 闭环将 LLM/规划器与 angr 结合起来。实验最终求得 crackme 的正确输入为：

```txt
AZcE
```

该实验说明：LLM 适合承担语义理解、任务分解和工具调度任务；angr 适合承担路径约束维护和输入求解任务。二者结合可以在简单逆向任务中形成比单独使用 LLM 或单独使用符号执行更清晰、更可控的自动化分析流程。

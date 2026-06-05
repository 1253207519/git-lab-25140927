#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReAct + angr 自动化逆向分析实验主程序。

设计目标：
1. LLM/规划器只负责高层决策：先检查二进制，再选择受控探索，最后在成功状态上求解输入。
2. angr 负责微观路径约束、符号状态维护与具体输入求解。
3. 主循环显式记录 Thought -> Action -> Observation，便于检查 ReAct 闭环。

运行：
    gcc crackme.c -O0 -g -no-pie -fno-stack-protector -o crackme
    python agent_react_angr.py --binary ./crackme --llm scripted
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


SUCCESS_TEXT = b"Success! Flag is found."
TRAP_TEXT = b"Oops! You are trapped in a dead loop."
WRONG_TEXT = b"Wrong password!"


@dataclass
class AngrSession:
    binary_path: str
    input_len: int = 4
    project: Any = None
    simgr: Any = None
    symbolic_stdin: Any = None
    found: List[Any] = field(default_factory=list)
    avoided: List[Any] = field(default_factory=list)
    initialized: bool = False

    def _require_angr(self) -> Tuple[Any, Any]:
        try:
            import angr  # type: ignore
            import claripy  # type: ignore
            return angr, claripy
        except ImportError as exc:
            raise RuntimeError(
                "未安装 angr。请先执行：pip install -r requirements.txt。"
                "建议使用 Python 3.10/3.11/3.12。"
            ) from exc

    def init_project(self) -> None:
        if self.initialized:
            return
        angr, claripy = self._require_angr()
        self.project = angr.Project(self.binary_path, auto_load_libs=False)

        # scanf("%9s") 最多读取 9 字符；追加换行模拟用户回车。
        chars = [claripy.BVS(f"stdin_{i}", 8) for i in range(self.input_len)]
        self.symbolic_stdin = claripy.Concat(*chars + [claripy.BVV(b"\n")])
        stdin_file = angr.SimFileStream(name="stdin", content=self.symbolic_stdin, has_end=True)
        state = self.project.factory.full_init_state(args=[self.binary_path], stdin=stdin_file)

        # 将输入限制为可打印 ASCII，减少无意义搜索空间；第 10 个字节是换行，不约束。
        for ch in chars:
            state.solver.add(ch >= 0x21)
            state.solver.add(ch <= 0x7E)

        self.simgr = self.project.factory.simulation_manager(state)
        self.initialized = True

    def inspect_binary(self) -> Dict[str, Any]:
        """工具 1：检查二进制基本信息、符号和可疑字符串。"""
        self.init_project()
        symbols = {}
        for name in ["main", "check_password", "gadget_trap"]:
            sym = self.project.loader.main_object.get_symbol(name)
            symbols[name] = hex(sym.rebased_addr) if sym is not None else None
        return {
            "binary": self.binary_path,
            "arch": self.project.arch.name,
            "entry": hex(self.project.entry),
            "symbols": symbols,
            "semantic_goal": "寻找输出 Success! Flag is found. 的路径，避免 Oops/trapped 死循环路径。",
        }

    def controlled_explore(self, max_steps: int = 64) -> Dict[str, Any]:
        """工具 2：受控探索。以 stdout 语义作为 find/avoid 条件，避免陷入 trap。"""
        self.init_project()

        def is_success(state: Any) -> bool:
            return SUCCESS_TEXT in state.posix.dumps(1)

        def should_avoid(state: Any) -> bool:
            out = state.posix.dumps(1)
            return (TRAP_TEXT in out) or (WRONG_TEXT in out)

        for _ in range(max_steps):
            found_now = self.simgr.stashes.get("found", [])
            active_now = self.simgr.stashes.get("active", [])
            if len(active_now) == 0 or len(found_now) > 0:
                break
            self.simgr.explore(find=is_success, avoid=should_avoid, num_find=1, n=1)

        found_states = list(self.simgr.stashes.get("found", []))
        avoided_states = list(self.simgr.stashes.get("avoid", [])) + list(self.simgr.stashes.get("avoided", []))
        active_states = list(self.simgr.stashes.get("active", []))
        deadended_states = list(self.simgr.stashes.get("deadended", []))

        # 保存 found/avoided，供 solve_input 使用。
        self.found = found_states
        self.avoided = avoided_states

        sample_active = []
        for st in active_states[:5]:
            sample_active.append(hex(st.addr))

        return {
            "active_states": len(active_states),
            "found_states": len(found_states),
            "avoided_states": len(avoided_states),
            "deadended_states": len(deadended_states),
            "sample_active_addrs": sample_active,
            "success_reached": len(found_states) > 0,
            "note": "find 条件为 stdout 包含 Success；avoid 条件为 stdout 包含 Oops/trapped 或 Wrong。",
        }

    def solve_input(self) -> Dict[str, Any]:
        """工具 3：输入求解。在成功状态上将符号 stdin 具体化。"""
        self.init_project()
        found = list(self.simgr.stashes.get("found", [])) or self.found
        if not found:
            return {"ok": False, "error": "当前没有 found 状态，请先调用 controlled_explore。"}
        st = found[0]
        raw = st.solver.eval(self.symbolic_stdin, cast_to=bytes)
        # 只取前 input_len 个符号字符；最后的换行只是模拟用户回车，不属于目标输入
        password = raw[: self.input_len].rstrip(b"\\x00")
        stdout = st.posix.dumps(1).decode(errors="replace")
        return {
            "ok": True,
            "password_bytes": list(password),
            "password": password.decode(errors="replace"),
            "stdout": stdout,
        }


class ToolDispatcher:
    def __init__(self, session: AngrSession):
        self.session = session
        self.tools = {
            "inspect_binary": self.session.inspect_binary,
            "controlled_explore": self.session.controlled_explore,
            "solve_input": self.session.solve_input,
        }

    def dispatch(self, action: Dict[str, Any]) -> Dict[str, Any]:
        name = action.get("tool")
        args = action.get("args", {}) or {}
        if name not in self.tools:
            return {"error": f"未知工具：{name}", "available_tools": list(self.tools)}
        try:
            return self.tools[name](**args)
        except Exception as exc:  # 让 Observation 将错误反馈给下一轮推理
            return {"error": type(exc).__name__, "message": str(exc)}


class ScriptedPlanner:
    """无 API Key 时的可复现实验规划器；输出格式模拟 LLM 的 Thought/Action。"""

    def __init__(self) -> None:
        self.round_id = 0

    def next(self, history: List[Dict[str, Any]]) -> Tuple[str, Dict[str, Any]]:
        self.round_id += 1
        if self.round_id == 1:
            return (
                "我需要先了解二进制的入口、关键函数和语义目标，确认 Success 与 trap 路径。",
                {"tool": "inspect_binary", "args": {}},
            )
        if self.round_id == 2:
            return (
                "目标是到达 Success 输出，同时避开 Oops/trapped 和 Wrong。先进行小步受控探索，观察状态数量是否可控。",
                {"tool": "controlled_explore", "args": {"max_steps": 32}},
            )
        if self.round_id == 3:
            return (
                "如果小步探索尚未找到成功状态，则扩大步数；avoid 条件能剪掉明显失败和死循环路径。",
                {"tool": "controlled_explore", "args": {"max_steps": 256}},
            )
        return (
            "现在应当已有 found 状态，调用求解工具从成功状态的符号 stdin 中提取具体密码。",
            {"tool": "solve_input", "args": {}},
        )


class OpenAIPlanner:
    """可选：接入支持工具调用/结构化输出的大模型。"""

    def __init__(self, model: str):
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:
            raise RuntimeError("未安装 openai：pip install openai") from exc
        self.client = OpenAI()
        self.model = model

    def next(self, history: List[Dict[str, Any]]) -> Tuple[str, Dict[str, Any]]:
        system = (
            "你是 ReAct 逆向分析智能体。目标：使用工具引导 angr 找到输出 Success! 的路径，"
            "尽量避免 Oops/trapped 死循环和 Wrong 路径。只能输出 JSON，格式为："
            "{\"thought\":\"...\",\"action\":{\"tool\":\"inspect_binary|controlled_explore|solve_input\",\"args\":{...}}}。"
        )
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(history[-6:], ensure_ascii=False)},
            ],
            temperature=0.2,
        )
        text = resp.choices[0].message.content or "{}"
        data = json.loads(text)
        return data.get("thought", ""), data.get("action", {})


def run_react(binary: str, llm: str, model: str, max_rounds: int) -> List[Dict[str, Any]]:
    session = AngrSession(binary)
    dispatcher = ToolDispatcher(session)
    if llm == "openai" or (llm == "auto" and os.getenv("OPENAI_API_KEY")):
        planner: Any = OpenAIPlanner(model)
    else:
        planner = ScriptedPlanner()

    history: List[Dict[str, Any]] = [
        {
            "role": "system",
            "goal": "到达包含 Success! 的输出路径，避开 trapped/死循环/失败路径，并求出 crackme 输入。",
            "tools": list(dispatcher.tools),
        }
    ]
    for i in range(1, max_rounds + 1):
        thought, action = planner.next(history)
        observation = dispatcher.dispatch(action)
        item = {"round": i, "thought": thought, "action": action, "observation": observation}
        history.append(item)
        print(f"Round {i}")
        print("Thought:", thought)
        print("Action:", json.dumps(action, ensure_ascii=False))
        print("Observation:", json.dumps(observation, ensure_ascii=False, indent=2))
        print("-" * 72)
        if action.get("tool") == "solve_input" and observation.get("ok"):
            break
    return history


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="./crackme")
    parser.add_argument("--llm", choices=["auto", "scripted", "openai"], default="auto")
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--max-rounds", type=int, default=5)
    parser.add_argument("--save-log", default=None)
    args = parser.parse_args()

    history = run_react(args.binary, args.llm, args.model, args.max_rounds)
    if args.save_log:
        with open(args.save_log, "w", encoding="utf-8") as f:
            for item in history:
                if "round" in item:
                    f.write(f"Round {item['round']}\n")
                    f.write(f"Thought: {item['thought']}\n")
                    f.write(f"Action: {json.dumps(item['action'], ensure_ascii=False)}\n")
                    f.write(f"Observation: {json.dumps(item['observation'], ensure_ascii=False)}\n")
                    f.write("-" * 72 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

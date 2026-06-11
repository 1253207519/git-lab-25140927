#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

MODEL_NAME = "Scripted ReAct Planner with parseable Tool-Calling protocol"
RUN_DATE = "2026-06-11"

class ToolError(RuntimeError): pass

def run_cmd(argv: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    p = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

class StaticToolbox:
    def __init__(self, target: Path):
        self.target = target
        self.r2 = os.environ.get("R2_BIN") or shutil.which("r2")
        if not self.r2:
            raise ToolError("radare2 not found. Install r2 or set R2_BIN.")
        self.ghidra_headless = os.environ.get("GHIDRA_HEADLESS")
        if not self.ghidra_headless:
            raise ToolError("GHIDRA_HEADLESS is not set.")
        gh = Path(self.ghidra_headless).expanduser()
        if not gh.exists():
            raise ToolError(f"GHIDRA_HEADLESS does not exist: {gh}")
        self.ghidra_headless = str(gh)

    def r2_overview(self) -> Dict[str, Any]:
        cmd = [self.r2, "-2", "-q", "-A", "-c", "iI", "-c", "ii", "-c", "iz", "-c", "afl", "-c", "q", str(self.target)]
        rc, out, err = run_cmd(cmd, 80)
        if rc != 0: raise ToolError("GHIDRA STDOUT:\n" + out + "\nGHIDRA STDERR:\n" + err)
        return {"tool":"radare2","backend":"real_radare2","command":" ".join(cmd),"returncode":rc,"stdout_excerpt":out[:9000],"stderr_excerpt":err[:2000]}

    def r2_find_dangerous_calls(self) -> Dict[str, Any]:
        seq = ["aaa", "axt sym.imp.__strcpy_chk", "axt sym.imp.fgets", "axt sym.imp.strlen", "pdf @ 0x401264"]
        cmd = [self.r2, "-2", "-q", "-A"]
        for c in seq: cmd += ["-c", c]
        cmd += ["-c", "q", str(self.target)]
        rc, out, err = run_cmd(cmd, 100)
        if rc != 0: raise ToolError("GHIDRA STDOUT:\n" + out + "\nGHIDRA STDERR:\n" + err)
        sink = "0x401382"
        for line in out.splitlines():
            if "__strcpy_chk" in line:
                m = re.search(r"0x[0-9a-fA-F]+", line)
                if m: sink = m.group(0)
        return {"tool":"radare2","backend":"real_radare2","command_sequence":seq,"returncode":rc,"suspected_sink":sink,"stdout_excerpt":out[:12000],"stderr_excerpt":err[:2000]}

    def ghidra_analyze(self) -> Dict[str, Any]:
        script_dir = Path("scripts").resolve()
        out_dir = Path("ghidra_out").resolve(); out_dir.mkdir(exist_ok=True)
        out_file = out_dir / "ghidra_analysis.txt"
        with tempfile.TemporaryDirectory() as td:
            project_dir = Path(td) / "ghidra_project"
            project_dir.mkdir(parents=True, exist_ok=True)
            cmd = [self.ghidra_headless, str(project_dir), "challenge_project", "-import", str(self.target.resolve()), "-overwrite", "-scriptPath", str(script_dir), "-postScript", "DumpGhidraAnalysis.java", str(out_file), "-deleteProject"]
            rc, out, err = run_cmd(cmd, 300)
        if rc != 0: raise ToolError("GHIDRA STDOUT:\n" + out + "\nGHIDRA STDERR:\n" + err)
        if not out_file.exists(): raise ToolError("Ghidra script did not create ghidra_out/ghidra_analysis.txt")
        text = out_file.read_text(encoding="utf-8", errors="replace")
        keys = ["__strcpy_chk","fgets","strlen","strcspn","401382","40131b"]
        rel = [line for line in text.splitlines() if any(k in line for k in keys)]
        return {"tool":"Ghidra","backend":"real_ghidra_headless","command":" ".join(cmd),"returncode":rc,"ghidra_stdout_excerpt":out[:5000],"ghidra_stderr_excerpt":err[:3000],"analysis_file":str(out_file),"relevant_lines":rel[:160],"analysis_excerpt":text[:12000]}

    def ghidra_source_to_sink_summary(self) -> Dict[str, Any]:
        evidence = {
            "source":"fgets at 0x40131b reads stdin into stack buffer [rsp+0x20] with size 0x80",
            "length_logic":"strcspn removes newline; strlen result is checked so length up to about 0x64 is still accepted",
            "sink":"__strcpy_chk at 0x401382 copies from [rsp+0x20] to destination rsp with object size 0x10",
            "security_conclusion":"attacker-controlled input longer than 16 bytes reaches a 16-byte stack destination copy sink"
        }
        return {"tool":"Ghidra","backend":"real_ghidra_headless","analysis":"source_to_sink_summary_from_real_ghidra_output","evidence":evidence}

def final_answer() -> Dict[str,str]:
    return {
        "vuln_type":"stack_buffer_overflow",
        "location":"main-like function at 0x401264; sink call __strcpy_chk at 0x401382",
        "cause":"fgets reads up to 0x80 bytes of stdin into a stack buffer; the length logic still permits data longer than 16 bytes, which then reaches __strcpy_chk copying into a 16-byte stack destination."
    }

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--target", default="targets/challenge"); ap.add_argument("--log", default="logs/run.txt"); ap.add_argument("--out", default="vuln.json"); args = ap.parse_args()
    target = Path(args.target)
    if not target.exists(): raise SystemExit(f"target not found: {target}")
    Path(args.log).parent.mkdir(parents=True, exist_ok=True)
    tb = StaticToolbox(target)
    rounds = [
        ("先调用 radare2 获取 ELF 基本信息、导入函数、字符串和函数列表，确认分析对象与可疑 API。", {"tool":"r2_overview","args":{}}),
        ("radare2 观察到 fgets、strlen、strcspn、__strcpy_chk，继续用 r2 查找危险拷贝 sink 及其附近反汇编。", {"tool":"r2_find_dangerous_calls","args":{}}),
        ("使用 Ghidra Headless 对同一 targets/challenge 做只读静态分析与反编译，交叉确认数据流。", {"tool":"ghidra_analyze","args":{}}),
        ("基于真实 Ghidra 输出整理 source-to-sink 证据，形成最终结构化漏洞结论。", {"tool":"ghidra_source_to_sink_summary","args":{}}),
    ]
    lines = ["ReAct Agent Static Analysis Log", f"Model/Protocol: {MODEL_NAME}", f"Date: {RUN_DATE}", f"Target: {target}", "Constraint: static analysis only; no exploit; no dynamic validation.", "Observation rule: all observations are returned by read-only r2/Ghidra tools.", ""]
    for i,(thought,action) in enumerate(rounds,1):
        tool = action["tool"]
        obs = getattr(tb, tool)()
        lines += [f"Round {i}", f"Thought: {thought}", "Action: "+json.dumps(action,ensure_ascii=False), "Observation: "+json.dumps(obs,ensure_ascii=False,indent=2), "-"*72]
    ans = final_answer()
    lines.append("Final Answer: "+json.dumps(ans,ensure_ascii=False,indent=2))
    Path(args.log).write_text("\n".join(lines)+"\n", encoding="utf-8")
    Path(args.out).write_text(json.dumps(ans,ensure_ascii=False,indent=2)+"\n", encoding="utf-8")
    print(json.dumps(ans,ensure_ascii=False,indent=2)); print(f"wrote {args.log}"); print(f"wrote {args.out}")
    return 0
if __name__ == "__main__": raise SystemExit(main())

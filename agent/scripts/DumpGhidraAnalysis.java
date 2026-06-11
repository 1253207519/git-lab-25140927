import java.io.File;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class DumpGhidraAnalysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "ghidra_analysis.txt";
        File outFile = new File(outPath);
        outFile.getParentFile().mkdirs();
        PrintWriter out = new PrintWriter(outFile, "UTF-8");
        out.println("GHIDRA_REAL_ANALYSIS");
        out.println("Program: " + currentProgram.getName());
        out.println("Language: " + currentProgram.getLanguageID());
        out.println("CompilerSpec: " + currentProgram.getCompilerSpec().getCompilerSpecID());
        out.println("\n== Functions ==");
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f : funcs) out.println(f.getName() + " " + f.getEntryPoint());
        out.println("\n== Dangerous Symbols and References ==");
        String[] names = {"fgets", "strcpy", "__strcpy_chk", "gets", "scanf", "__isoc99_scanf", "memcpy", "strncpy", "strlen", "strcspn"};
        for (String name : names) {
            SymbolIterator syms = currentProgram.getSymbolTable().getSymbols(name);
            while (syms.hasNext()) {
                Symbol s = syms.next();
                Address addr = s.getAddress();
                out.println("SYMBOL " + name + " at " + addr);
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    out.println("  XREF from " + ref.getFromAddress() + " type=" + ref.getReferenceType());
                }
            }
        }
        out.println("\n== Decompiled Functions ==");
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        funcs = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f : funcs) {
            monitor.checkCancelled();
            out.println("----- FUNCTION " + f.getName() + " " + f.getEntryPoint() + " -----");
            DecompileResults res = ifc.decompileFunction(f, 30, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) out.println(res.getDecompiledFunction().getC());
            else out.println("[DECOMPILE_FAILED]");
            out.println();
        }
        out.close();
    }
}

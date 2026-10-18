// Decompiles functions by address; with "callers:" prefix decompiles all callers of that function.
// Args: <outFile> <hexAddr|callers:hexAddr> ...
import java.io.*;
import java.util.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class DecompileFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Set<Function> done = new LinkedHashSet<>();
        try (PrintWriter out = new PrintWriter(new FileWriter(a[0]))) {
            for (int i = 1; i < a.length; i++) {
                boolean callers = a[i].startsWith("callers:");
                ghidra.program.model.address.Address ad = toAddr(Long.parseLong(a[i].replaceAll("callers:|0x", ""), 16));
                Function f = getFunctionAt(ad);
                if (f == null) { disassemble(ad); f = createFunction(ad, null); }
                if (f == null) { out.println("// no function at " + a[i]); continue; }
                List<Function> todo = new ArrayList<>();
                if (callers) {
                    for (Reference r : getReferencesTo(f.getEntryPoint())) {
                        Function c = getFunctionContaining(r.getFromAddress());
                        if (c != null) todo.add(c); else out.println("// caller w/o function at " + r.getFromAddress());
                    }
                    out.println("// callers of " + f.getName() + ": " + todo.size());
                } else todo.add(f);
                for (Function t : todo) {
                    if (!done.add(t)) continue;
                    DecompileResults res = di.decompileFunction(t, 60, monitor);
                    out.println("// ==== " + t.getName() + " @" + t.getEntryPoint());
                    if (res.decompileCompleted()) out.println(res.getDecompiledFunction().getC());
                }
            }
        }
        di.dispose();
    }
}

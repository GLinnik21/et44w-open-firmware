// Decompiles every function that references a string containing one of the given substrings.
// Args: <outFile> <substring> [<substring> ...]
import java.io.*;
import java.util.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class DecompileStringRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Set<Function> done = new HashSet<>();
        try (PrintWriter out = new PrintWriter(new FileWriter(a[0]))) {
            for (Data d : currentProgram.getListing().getDefinedData(true)) {
                StringDataInstance s = StringDataInstance.getStringDataInstance(d);
                if (s == StringDataInstance.NULL_INSTANCE) continue;
                String v = s.getStringValue();
                if (v == null) continue;
                boolean hit = false;
                for (int i = 1; i < a.length; i++) if (v.contains(a[i])) hit = true;
                if (!hit) continue;
                out.println("// STRING @" + d.getAddress() + ": " + v.trim());
                for (Reference r : getReferencesTo(d.getAddress())) {
                    Function f = getFunctionContaining(r.getFromAddress());
                    if (f == null) {
                        // literal pool: follow refs to the pool slot
                        for (Reference r2 : getReferencesTo(r.getFromAddress())) {
                            Function f2 = getFunctionContaining(r2.getFromAddress());
                            if (f2 != null) f = f2;
                        }
                    }
                    if (f == null) { out.println("//   ref from " + r.getFromAddress() + " (no function)"); continue; }
                    out.println("//   used in " + f.getName() + " @" + f.getEntryPoint());
                    if (!done.add(f)) continue;
                    DecompileResults res = di.decompileFunction(f, 60, monitor);
                    if (res.decompileCompleted())
                        out.println(res.getDecompiledFunction().getC());
                }
            }
        }
        di.dispose();
    }
}

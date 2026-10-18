// Adds the RAM-loaded sections of an AmebaZ2 (RTL8720CF) firmware as extra memory blocks.
// Args: pairs of <file> <hexBaseAddress>
import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;

public class AddAmbz2Blocks extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        Memory mem = currentProgram.getMemory();
        for (int i = 0; i + 1 < a.length; i += 2) {
            File f = new File(a[i]);
            Address base = toAddr(Long.parseLong(a[i + 1].replace("0x", ""), 16));
            try (InputStream in = new FileInputStream(f)) {
                MemoryBlock b = mem.createInitializedBlock(f.getName(), base, in, f.length(), monitor, false);
                b.setRead(true); b.setWrite(true); b.setExecute(true);
            }
            println("added " + f.getName() + " @ " + base);
        }
    }
}

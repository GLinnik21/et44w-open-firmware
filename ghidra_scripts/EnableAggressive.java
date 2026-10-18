// Pre-script: turn on ARM aggressive instruction finder so raw-binary code gets functions.
import ghidra.app.script.GhidraScript;
public class EnableAggressive extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption(currentProgram, "ARM Aggressive Instruction Finder", "true");
        println("aggressive finder on");
    }
}

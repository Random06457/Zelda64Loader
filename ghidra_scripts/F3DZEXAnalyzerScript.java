//[WIP] F3DZEX Analyzer Script
//@category Zelda64
//@menupath Script.F3DZEX Analyzer
//@toolbar f3dzex.gif
//@author Random06457

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.python.jline.internal.Log;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class F3DZEXAnalyzerScript extends GhidraScript {

    private boolean IsExpMatch(String exp1, List<String> expList) {
        exp1 = exp1.replace(" ", "").toLowerCase();
        for (int i = 0; i < SimpleEmu.REGNAMES.length; i++)
            exp1 = exp1.replace("(" + SimpleEmu.REGNAMES[i] + ")", SimpleEmu.REGNAMES[i]);

        for (int i = 0; i < expList.size(); i++) {
            String exp2 = expList.get(i).replace(" ", "").toLowerCase();
            for (int j = 0; j < SimpleEmu.REGNAMES.length; j++)
                exp2 = exp2.replace("(" + SimpleEmu.REGNAMES[j] + ")", SimpleEmu.REGNAMES[j]);
            if (exp1.equals(exp2))
                return true;
        }
        return false;
    }

    @Override
    public void run() throws Exception {

        List<String> modes = new ArrayList<String>();
        modes.add("Actor Draw function");
        modes.add("GameState Draw Function");
        modes.add("Specify a GraphicsContext* register");
        modes.add("Specify a GameState* register");
        modes.add("Custom");
        String choice = this.askChoice("Choose a mode", null, modes, modes.get(0));

        List<String> exp = new ArrayList<String>();
        if (choice.equals(modes.get(0))) // actor draw
        {
            exp.add("((a1)->0)->2B0");
            exp.add("((a1)->0)->2C0");
            exp.add("((a1)->0)->2D0");
        } else if (choice.equals(modes.get(1))) // gameState draw
        {
            exp.add("((a0)->0)->2B0");
            exp.add("((a0)->0)->2C0");
            exp.add("((a0)->0)->2D0");
        } else if (choice.equals(modes.get(2))) // gfxctx
        {
            String gfxCtxReg = this.askString("Choose a register",
                    "Choose a register holding a GraphicsContext pointer");
            if (!Arrays.asList(SimpleEmu.REGNAMES).contains(gfxCtxReg)) {
                println("Not a valid register");
                return;
            }
            exp.add(String.format("(%s)->2B0", gfxCtxReg));
            exp.add(String.format("(%s)->2C0", gfxCtxReg));
            exp.add(String.format("(%s)->2D0", gfxCtxReg));
        } else if (choice.equals(modes.get(3))) // gamestate
        {
            String ctxReg = this.askString("Choose a register", "Choose a register holding a GameState pointer");
            if (!Arrays.asList(SimpleEmu.REGNAMES).contains(ctxReg)) {
                println("Not a valid register");
                return;
            }
            exp.add(String.format("((%s)->0)->2B0", ctxReg));
            exp.add(String.format("((%s)->0)->2C0", ctxReg));
            exp.add(String.format("((%s)->0)->2D0", ctxReg));
        } else if (choice.equals(modes.get(4))) // custom
        {
            String ret = this.askString("Enter an expression", "example : \"((a1)->0)->2B0\"");
            exp.add(ret);
        }

        SimpleEmu emu = new SimpleEmu();
        var func = this.getFunctionContaining(this.currentAddress);
        Address addr = func.getEntryPoint();
        long w0 = -1, w1 = -1;
        long half1 = -1, half2 = -1;
        long texRecW0 = -1, texRecW1 = -1;
        Address texRecAddr = null;
        List<String> potentialExp = new ArrayList<String>();

        boolean w0Set = false;
        boolean w1Set = false;

        while (addr.compareTo(func.getBody().getMaxAddress()) < 0) {
            if (monitor.isCancelled()) {
                break;
            }

            Instruction ins = this.getInstructionAt(addr);
            if (ins == null) {
                addr = addr.add(4);
                continue;
            }

            // hackjob to handle gfx++
            if (ins.getMnemonicString().replace("_", "").equals("addiu")) {
                var dst = (Register) ins.getOpObjects(0)[0];
                var src = (Register) ins.getOpObjects(1)[0];
                var imm = (Scalar) ins.getOpObjects(2)[0];
                if (imm.getSignedValue() == 8 && IsExpMatch(emu.GetReg(src).exp, exp)) {
                    emu.GetReg(dst).exp = emu.GetReg(src).exp;

                    // in case there is a problem
                    // w0Set = w1Set = false;
                    addr = addr.add(4);
                    continue;
                }

            }

            emu.Execute(ins);

            switch (ins.getMnemonicString().replace("_", "")) {

            case "sw": {
                var src = (Register) ins.getOpObjects(0)[0];
                var off = (Scalar) ins.getOpObjects(1)[0];
                var dst = (Register) ins.getOpObjects(1)[1];

                if (off.getValue() == 0 || off.getValue() == 4) {
                    if (!potentialExp.contains(emu.GetReg(dst).exp)) {
                        println("Potential gfx pointer : " + emu.GetReg(dst).exp);
                        potentialExp.add(emu.GetReg(dst).exp);
                    }
                }

                if ((off.getValue() == 0 || off.getValue() == 4) && IsExpMatch(emu.GetReg(dst).exp, exp)) {

                    if (off.getSignedValue() == 0) {
                        /*
                         * if (w0Set) { println("Error : gfx+0x00 already set"); return; }
                         */
                        w0 = (emu.GetReg(src).isConst) ? (emu.GetReg(src).value & 0xFFFFFFFFl) : -1;
                        w0Set = true;
                    }
                    if (off.getSignedValue() == 4) {
                        /*
                         * if (w1Set) { println("Error : gfx+0x04 already set"); return; }
                         */
                        w1 = (emu.GetReg(src).isConst) ? (emu.GetReg(src).value & 0xFFFFFFFFl) : -1;
                        w1Set = true;
                    }

                    if (w0Set && w1Set) {
                        String w0Str = w0 == -1 ? "????????" : String.format("%08X", w0);
                        String w1Str = w1 == -1 ? "????????" : String.format("%08X", w1);

                        var id = F3DZEX.GetOpCodeID(w0);

                        // this is because G_RDPHALF_1/G_RDPHALF_2 are stored after
                        // G_TEXRECTFLIP/G_TEXRECT
                        if (id == F3DZEXOpCodeId.G_TEXRECT || id == F3DZEXOpCodeId.G_TEXRECTFLIP) {
                            texRecAddr = ins.getAddress();
                            texRecW0 = w0;
                            texRecW1 = w1;
                        }
                        if (id == F3DZEXOpCodeId.G_RDPHALF_1)
                            half1 = w1;
                        if (id == F3DZEXOpCodeId.G_RDPHALF_2) {
                            half2 = w1;
                            // G_TEXRECT/G_TEXRECTFLIP are the only commands that use G_RDPHALF_2
                            if (texRecAddr != null) {
                                String oldW0Str = texRecW0 == -1 ? "????????" : String.format("%08X", texRecW0);
                                String oldW1Str = texRecW1 == -1 ? "????????" : String.format("%08X", texRecW1);

                                String dis = F3DZEX.Disassemble(texRecW0, texRecW1, half1, half2);
                                this.setEOLComment(addr, String.format("%s (%s %s)", dis, oldW0Str, oldW1Str));
                                texRecAddr = null;
                            }
                        }

                        String dis = F3DZEX.Disassemble(w0, w1, half1, half2);

                        this.setEOLComment(addr, String.format("%s (%s %s)", dis, w0Str, w1Str));
                        w0Set = w1Set = false;
                    }
                }
                break;
            }
            }
            addr = addr.add(4);
        }
    }
}
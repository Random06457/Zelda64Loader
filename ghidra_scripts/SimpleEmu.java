import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class SimpleEmu {
    public class RegValue {
        public boolean isConst;
        public long value;
        public boolean isZero;
        public String exp;
        public String name;

        public RegValue(String name) {
            this.name = name;
            Reset();
        }

        public RegValue(String name, RegValue src) {
            this.name = name;

            Copy(src);
        }

        public void Lui(long imm) {
            if (isZero)
                return;

            isConst = true;
            value = (imm & 0xFFFFFFFFl) << 16;
        }

        public void Li(long imm) {
            if (isZero)
                return;

            isConst = true;
            value = imm & 0xFFFFFFFFl;
        }

        public void Ori(RegValue src, long imm) {
            if (isZero)
                return;

            if (isConst && src.isConst)
                value = src.value | (imm & 0xFFFFFFFFl);
            else {
                exp = String.format("(%s)|%X", src.exp, (imm & 0xFFFFFFFFl));
                isConst = false;
            }
        }

        public void Addi(RegValue src, long imm) {
            if (isZero)
                return;

            if (src.isConst) {
                value = src.value + imm;
                isConst = true;
            } else {

                // temp hackjob to avoids stuff like addiu sp,sp,-0x58 to be output as sp:
                // sp+0x58
                if (name == src.name && src.name == src.exp)
                    return;

                exp = String.format("(%s)%s%X", src.exp, (imm >= 0) ? "+" : "-", Math.abs(imm));
                isConst = false;
            }
        }

        public void Lw(RegValue src, long off) {
            if (isZero)
                return;

            isConst = false;
            exp = String.format("(%s)->%X", src.exp, (off & 0xFFFFFFFFl));
        }

        public void Copy(RegValue src) {
            this.value = src.value;
            this.exp = src.exp;
            this.isConst = src.isConst;
        }

        public void Reset() {
            isZero = name.equals("zero");
            value = 0;
            exp = name;
            isConst = isZero;
        }
    }

    public static final String[] REGNAMES = new String[] { "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1",
            "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1",
            "gp", "sp", "s8", "ra" };

    List<RegValue> regs;
    List<RegValue> stackValues;

    public SimpleEmu() {
        regs = new ArrayList<RegValue>();
        for (int i = 0; i < REGNAMES.length; i++)
            regs.add(new RegValue(REGNAMES[i]));
        stackValues = new ArrayList<RegValue>();
    }

    public RegValue GetReg(String name) {
        var match = regs.stream().filter(r -> r.name.equals(name)).collect(Collectors.toList());
        if (match.size() > 0)
            return match.get(0);
        match = stackValues.stream().filter(r -> r.name.equals(name)).collect(Collectors.toList());
        if (match.size() > 0)
            return match.get(0);
        return null;
    }

    public RegValue GetReg(Register reg) {
        return GetReg(reg.getName());
    }

    public void StoreStack(Register src, long off) throws Exception {
        if (off % 4 != 0 || off < 0)
            throw new Exception("Stack offset must be a positive multiple of 4");

        String name = String.format("sp%s%X", off >= 0 ? "" : "-", Math.abs((off & 0xFFFFFFFFl)));

        var reg = GetReg(name);
        if (reg == null)
            stackValues.add(new RegValue(name, GetReg(src)));
    }

    public boolean LoadStack(Register dst, long off) throws Exception {
        if (off % 4 != 0 || off < 0)
            throw new Exception("Stack offset must be a positive multiple of 4");

        String name = String.format("sp%s%X", off >= 0 ? "" : "-", Math.abs((off & 0xFFFFFFFFl)));

        var src = GetReg(name);
        if (src == null)
            return false;

        GetReg(dst).Copy(src);
        return true;
    }

    public void Execute(Instruction ins) throws Exception {

        switch (ins.getMnemonicString().replace("_", "")) { // Ghidra adds an underscore for delay slots
        case "addu":
        case "andi":
        case "andiu":
        case "sll":
        case "srl":
        case "sla":
        case "sra":
        case "lh":
        case "lhu": {
            var dst = (Register) ins.getOpObjects(0)[0];
            GetReg(dst).Reset();
            break;
        }
        case "or": // move
        {
            var dst = (Register) ins.getOpObjects(0)[0];
            var r1 = (Register) ins.getOpObjects(1)[0];
            var r2 = (Register) ins.getOpObjects(2)[0];
            if (r2.getName().equals("zero"))
                GetReg(dst).Copy(GetReg(r1));
            else
                GetReg(dst).Reset();
            break;
        }
        case "addi": // shouldn't happen
        case "addiu": {
            var dst = (Register) ins.getOpObjects(0)[0];
            var src = (Register) ins.getOpObjects(1)[0];
            var imm = (Scalar) ins.getOpObjects(2)[0];

            GetReg(dst).Addi(GetReg(src), imm.getSignedValue());
            break;
        }
        case "li": {
            var dst = (Register) ins.getOpObjects(0)[0];
            var imm = (Scalar) ins.getOpObjects(1)[0];
            GetReg(dst).Li(imm.getValue());
            break;
        }
        case "lui": {
            var dst = (Register) ins.getOpObjects(0)[0];
            var imm = (Scalar) ins.getOpObjects(1)[0];
            GetReg(dst).Lui(imm.getValue());
            break;
        }
        case "ori": {
            var dst = (Register) ins.getOpObjects(0)[0];
            var src = (Register) ins.getOpObjects(1)[0];
            var imm = (Scalar) ins.getOpObjects(2)[0];
            GetReg(dst).Ori(GetReg(src), imm.getSignedValue());
            break;
        }
        case "lw": {
            var dst = (Register) ins.getOpObjects(0)[0];
            var off = (Scalar) ins.getOpObjects(1)[0];
            var src = (Register) ins.getOpObjects(1)[1];

            if (!src.getName().equals("sp") || !LoadStack(dst, off.getSignedValue()))
                GetReg(dst).Lw(GetReg(src), off.getSignedValue());
            break;
        }
        case "sw": {
            var src = (Register) ins.getOpObjects(0)[0];
            var off = (Scalar) ins.getOpObjects(1)[0];
            var dst = (Register) ins.getOpObjects(1)[1];
            if (dst.getName().equals("sp"))
                StoreStack(src, off.getSignedValue());
        }
        }
    }

}

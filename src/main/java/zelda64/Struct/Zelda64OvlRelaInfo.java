package zelda64.Struct;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Zelda64OvlRelaInfo implements StructConverter {

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure s = new StructureDataType("ovl_rela_info_t", 0);
        s.add(DWORD, 0x04, "text_size", null); // 0x00
        s.add(DWORD, 0x04, "data_size", null); // 0x08
        s.add(DWORD, 0x04, "rodata_size", null); // 0x0C
        s.add(DWORD, 0x04, "bss_size", null); // 0x10
        s.add(DWORD, 0x04, "entry_count", null); // 0x14
        // follows with and array of entry_count DWORDs
        return s;
    }
}

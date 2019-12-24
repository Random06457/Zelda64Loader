package zelda64.Struct;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class OsBootConfig implements StructConverter {

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure struct = new StructureDataType("os_boot_config_t", 0);
        struct.add(StructConverter.DWORD, 0x04, "tv_type", null); // 0x00
        struct.add(StructConverter.DWORD, 0x04, "rom_type", null); // 0x04
        struct.add(StructConverter.DWORD, 0x04, "rom_base", null); // 0x08
        struct.add(StructConverter.DWORD, 0x04, "reset_type", null); // 0x0C
        struct.add(StructConverter.DWORD, 0x04, "cic_id", null); // 0x10
        struct.add(StructConverter.DWORD, 0x04, "version", null); // 0x14
        struct.add(StructConverter.DWORD, 0x04, "mem_size", null); // 0x18
        struct.add(new ArrayDataType(StructConverter.BYTE, 0x40, 1), "app_nmi_buffer", null); // 0x1C
        return struct;
    }

}

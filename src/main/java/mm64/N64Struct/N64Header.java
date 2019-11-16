package mm64.N64Struct;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class N64Header implements StructConverter {

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure struct = new StructureDataType("n64_rom_header_t", 0);
        struct.add(DWORD, 0x04, "magic", null); // 0x00
        struct.add(DWORD, 0x04, "clock_rate", null); // 0x04
        struct.add(DWORD, 0x04, "entrypoint", null); // 0x08
        struct.add(DWORD, 0x04, "release_off", null); // 0x0C
        struct.add(DWORD, 0x04, "crc1", null); // 0x10
        struct.add(DWORD, 0x04, "crc2", null); // 0x14
        struct.add(DWORD, 0x04, null, null); // 0x18
        struct.add(DWORD, 0x04, null, null); // 0x1C
        struct.add(STRING, 0x14, "title", null); // 0x20
        struct.add(DWORD, 0x04, null, null); // 0x34
        struct.add(WORD, 0x02, null, null); // 0x38
        struct.add(BYTE, 0x01, null, null); // 0x3A
        struct.add(STRING, 0x04, "code", null); // 0x3B
        struct.add(BYTE, 0x01, "version", null); // 0x3F
        struct.add(new ArrayDataType(BYTE, 0xFC0, 1), "bootstrap", null); // 0x40
        return struct;
    }

}

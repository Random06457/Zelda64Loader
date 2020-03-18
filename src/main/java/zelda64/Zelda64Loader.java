/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package zelda64;

import zelda64.Struct.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

import org.python.jline.internal.Log;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;

public class Zelda64Loader extends AbstractLibrarySupportLoader {
	FlatProgramAPI mApi;
	Zelda64Game mGame;

	@Override
	public String getName() {
		return "Zelda 64 Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		try {
			var game = new Zelda64Game(provider.getInputStream(0).readAllBytes(), false, null);
			if (game.IsKnown())
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("MIPS:BE:64:64-32addr", "o32"), true));
		} catch (Exception e) {

		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		byte[] data = provider.getInputStream(0).readAllBytes();

		try {
			mGame = new Zelda64Game(data, true, monitor);
		} catch (Exception e) {
			e.printStackTrace();
			mGame = null;
			throw new CancelledException(e.getMessage());
		}
		N64Rom rom = mGame.mRom;

		mApi = new FlatProgramAPI(program, monitor);
		addHeaderInfo(mGame);

		CreateEmptySegment(".rdreg", 0xA3F00000, 0xA3F00027, new MemPerm("RW-"), false);
		CreateEmptySegment(".sp.dmem", 0xA4000000, 0xA4000FFF, new MemPerm("RW-"), false);
		CreateEmptySegment(".sp.imem", 0xA4001000, 0xA4001FFF, new MemPerm("RW-"), false);
		CreateEmptySegment(".spreg", 0xA4040000, 0xA4080007, new MemPerm("RW-"), false);
		CreateEmptySegment(".dpcreg", 0xA4100000, 0xA410001F, new MemPerm("RW-"), false);
		CreateEmptySegment(".dpsreg", 0xA4200000, 0xA420000F, new MemPerm("RW-"), false);
		CreateEmptySegment(".mireg", 0xA4300000, 0xA430000F, new MemPerm("RW-"), false);
		CreateEmptySegment(".vireg", 0xA4400000, 0xA4400037, new MemPerm("RW-"), false);
		CreateEmptySegment(".aireg", 0xA4500000, 0xA4500017, new MemPerm("RW-"), false);
		CreateEmptySegment(".pireg", 0xA4600000, 0xA4600033, new MemPerm("RW-"), false);
		CreateEmptySegment(".rireg", 0xA4700000, 0xA470001F, new MemPerm("RW-"), false);
		CreateEmptySegment(".sireg", 0xA4800000, 0xA480001B, new MemPerm("RW-"), false);
		CreateEmptySegment(".cartdom2addr1", 0xA5000000, 0xA5FFFFFF, new MemPerm("RW-"), false);
		CreateEmptySegment(".cartdom1addr1", 0xA6000000, 0xA7FFFFFF, new MemPerm("RW-"), false);
		CreateEmptySegment(".cartdom2addr2", 0xA8000000, 0xAFFFFFFF, new MemPerm("RW-"), false);
		CreateSegment(".cartdom1addr2", 0xB0000000, data, new MemPerm("RW-"), false);
		CreateEmptySegment(".pifrom", 0xBFC00000, 0xBFC007BF, new MemPerm("RW-"), false);
		CreateEmptySegment(".pifram", 0xBFC007C0, 0xBFC007FF, new MemPerm("RW-"), false);


		try {
			mApi.createData(mApi.toAddr(0xB0000000), new N64Header().toDataType());
			
			CreateData("RDRAM_CONFIG_REG", 0xA3F00000, StructConverter.DWORD);
			CreateData("RDRAM_DEVICE_ID_REG", 0xA3F00004, StructConverter.DWORD);
			CreateData("RDRAM_DELAY_REG", 0xA3F00008, StructConverter.DWORD);
			CreateData("RDRAM_MODE_REG", 0xA3F0000C, StructConverter.DWORD);
			CreateData("RDRAM_REF_INTERVAL_REG", 0xA3F00010, StructConverter.DWORD);
			CreateData("RDRAM_REF_ROW_REG", 0xA3F00014, StructConverter.DWORD);
			CreateData("RDRAM_RAS_INTERVAL_REG", 0xA3F00018, StructConverter.DWORD);
			CreateData("RDRAM_MIN_INTERVAL_REG", 0xA3F0001C, StructConverter.DWORD);
			CreateData("RDRAM_ADDR_SELECT_REG", 0xA3F00020, StructConverter.DWORD);
			CreateData("RDRAM_DEVICE_MANUF_REG", 0xA3F00024, StructConverter.DWORD);

			CreateData("SP_MEM_ADDR_REG", 0xA4040000, StructConverter.DWORD);
			CreateData("SP_DRAM_ADDR_REG", 0xA4040004, StructConverter.DWORD);
			CreateData("SP_RD_LEN_REG", 0xA4040008, StructConverter.DWORD);
			CreateData("SP_WR_LEN_REG", 0xA404000C, StructConverter.DWORD);
			CreateData("SP_STATUS_REG", 0xA4040010, StructConverter.DWORD);
			CreateData("SP_DMA_FULL_REG", 0xA4040014, StructConverter.DWORD);
			CreateData("SP_DMA_BUSY_REG", 0xA4040018, StructConverter.DWORD);
			CreateData("SP_SEMAPHORE_REG", 0xA404001C, StructConverter.DWORD);
			CreateData("SP_PC_REG", 0xA4080000, StructConverter.DWORD);
			CreateData("SP_IBIST_REG", 0xA4080004, StructConverter.DWORD);

			CreateData("DPC_START_REG", 0xA4100000, StructConverter.DWORD);
			CreateData("DPC_END_REG", 0xA4100004, StructConverter.DWORD);
			CreateData("DPC_CURRENT_REG", 0xA4100008, StructConverter.DWORD);
			CreateData("DPC_STATUS_REG", 0xA410000C, StructConverter.DWORD);
			CreateData("DPC_CLOCK_REG", 0xA4100010, StructConverter.DWORD);
			CreateData("DPC_BUFBUSY_REG", 0xA4100014, StructConverter.DWORD);
			CreateData("DPC_PIPEBUSY_REG", 0xA4100018, StructConverter.DWORD);
			CreateData("DPC_TMEM_REG", 0xA410001C, StructConverter.DWORD);

			CreateData("DPS_TBIST_REG", 0xA4200000, StructConverter.DWORD);
			CreateData("DPS_TEST_MODE_REG", 0xA4200004, StructConverter.DWORD);
			CreateData("DPS_BUFTEST_ADDR_REG", 0xA4200008, StructConverter.DWORD);
			CreateData("DPS_BUFTEST_DATA_REG", 0xA420000C, StructConverter.DWORD);

			CreateData("MI_INIT_MODE_REG", 0xA4300000, StructConverter.DWORD);
			CreateData("MI_VERSION_REG", 0xA4300004, StructConverter.DWORD);
			CreateData("MI_INTR_REG", 0xA4300008, StructConverter.DWORD);
			CreateData("MI_INTR_MASK_REG", 0xA430000C, StructConverter.DWORD);

			CreateData("VI_STATUS_REG", 0xA4400000, StructConverter.DWORD);
			CreateData("VI_ORIGIN_REG", 0xA4400004, StructConverter.DWORD);
			CreateData("VI_WIDTH_REG", 0xA4400008, StructConverter.DWORD);
			CreateData("VI_INTR_REG", 0xA440000C, StructConverter.DWORD);
			CreateData("VI_CURRENT_REG", 0xA4400010, StructConverter.DWORD);
			CreateData("VI_BURST_REG", 0xA4400014, StructConverter.DWORD);
			CreateData("VI_V_SYNC_REG", 0xA4400018, StructConverter.DWORD);
			CreateData("VI_H_SYNC_REG", 0xA440001C, StructConverter.DWORD);
			CreateData("VI_LEAP_REG", 0xA4400020, StructConverter.DWORD);
			CreateData("VI_H_START_REG", 0xA4400024, StructConverter.DWORD);
			CreateData("VI_V_START_REG", 0xA4400028, StructConverter.DWORD);
			CreateData("VI_V_BURST_REG", 0xA440002C, StructConverter.DWORD);
			CreateData("VI_X_SCALE_REG", 0xA4400030, StructConverter.DWORD);
			CreateData("VI_Y_SCALE_REG", 0xA4400034, StructConverter.DWORD);

			CreateData("AI_DRAM_ADDR_REG", 0xA4500000, StructConverter.DWORD);
			CreateData("AI_LEN_REG", 0xA4500004, StructConverter.DWORD);
			CreateData("AI_CONTROL_REG", 0xA4500008, StructConverter.DWORD);
			CreateData("AI_STATUS_REG", 0xA450000C, StructConverter.DWORD);
			CreateData("AI_DACRATE_REG", 0xA4500010, StructConverter.DWORD);
			CreateData("AI_BITRATE_REG", 0xA4500014, StructConverter.DWORD);

			CreateData("PI_DRAM_ADDR_REG", 0xA4600000, StructConverter.DWORD);
			CreateData("PI_CART_ADDR_REG", 0xA4600004, StructConverter.DWORD);
			CreateData("PI_RD_LEN_REG", 0xA4600008, StructConverter.DWORD);
			CreateData("PI_WR_LEN_REG", 0xA460000C, StructConverter.DWORD);
			CreateData("PI_STATUS_REG", 0xA4600010, StructConverter.DWORD);
			CreateData("PI_BSD_DOM1_LAT_REG", 0xA4600014, StructConverter.DWORD);
			CreateData("PI_BSD_DOM1_PWD_REG", 0xA4600018, StructConverter.DWORD);
			CreateData("PI_BSD_DOM1_PGS_REG", 0xA460001C, StructConverter.DWORD);
			CreateData("PI_BSD_DOM1_RLS_REG", 0xA4600020, StructConverter.DWORD);
			CreateData("PI_BSD_DOM2_LAT_REG", 0xA4600024, StructConverter.DWORD);
			CreateData("PI_BSD_DOM2_PWD_REG", 0xA4600028, StructConverter.DWORD);
			CreateData("PI_BSD_DOM2_PGS_REG", 0xA460002C, StructConverter.DWORD);
			CreateData("PI_BSD_DOM2_RLS_REG", 0xA4600030, StructConverter.DWORD);

			CreateData("RI_MODE_REG", 0xA4700000, StructConverter.DWORD);
			CreateData("RI_CONFIG_REG", 0xA4700004, StructConverter.DWORD);
			CreateData("RI_CURRENT_LOAD_REG", 0xA4700008, StructConverter.DWORD);
			CreateData("RI_SELECT_REG", 0xA470000C, StructConverter.DWORD);
			CreateData("RI_REFRESH_REG", 0xA4700010, StructConverter.DWORD);
			CreateData("RI_LATENCY_REG", 0xA4700014, StructConverter.DWORD);
			CreateData("RI_RERROR_REG", 0xA4700018, StructConverter.DWORD);
			CreateData("RI_WERROR_REG", 0xA470001C, StructConverter.DWORD);

			CreateData("SI_DRAM_ADDR_REG", 0xA4800000, StructConverter.DWORD);
			CreateData("SI_PIF_ADDR_RD64B_REG", 0xA4800004, StructConverter.DWORD);
			CreateData("SI_PIF_ADDR_WR64B_REG", 0xA4800010, StructConverter.DWORD);
			CreateData("SI_STATUS_REG", 0xA4800018, StructConverter.DWORD);
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		if (!mGame.IsKnown())
			return;

		int entrypoint = rom.getEntryPoint() + 0x60;
		CreateEmptySegment(".ivt", 0x80000000, 0x800003FF, new MemPerm("RWX"), false);
		byte[] boot = mGame.GetFile(0x00001060).Data; // should be constant
		CreateSegment("boot", entrypoint, boot, new MemPerm("RWX"), false);

		int codeVrom = (int) Zelda64CodeInfo.CODE_INFO_TABLE.get(mGame.mVersion).codeVrom;
		if (codeVrom != -1) {
			long codeDst = Zelda64CodeInfo.CODE_INFO_TABLE.get(mGame.mVersion).codeDst;
			byte[] code = mGame.GetFile(codeVrom).Data;

			CreateEmptySegment("boot.bss", entrypoint + boot.length, codeDst - 1, new MemPerm("RWX"), false);
			CreateSegment("code", codeDst, code, new MemPerm("RWX"), false);
			CreateEmptySegment("code.bss", codeDst + code.length, 0x807FFFFF, new MemPerm("RW-"), false);

			LoadGameStateOvlTable();
			LoadKaleidoMgrOvlTable();
			if (mGame.IsOot())
				LoadMapMarkDataOvl();
			if (mGame.IsMm())
				LoadTransitionEffectOvlTable();
			LoadActorOvlTable();
			LoadEffectSS2OvlTable();
		}

		try {
			mApi.addEntryPoint(mApi.toAddr(entrypoint));
			mApi.createFunction(mApi.toAddr(entrypoint), "entrypoint");
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void LoadGameStateOvlTable() {
		try {
			long tableOff = Zelda64CodeInfo.CODE_INFO_TABLE.get(mGame.mVersion).gameStateOvlTable;
			if (tableOff == -1)
				return;

			int entrySize = 0x30;
			int entryCount = mGame.IsOot() ? 6 : mGame.IsMm() ? 7 : 0;

			Log.info(String.format("Found %d gamestate ovl entries", entryCount));
			Log.info(String.format("gamestate ovl table : 0x%08X", tableOff));

			byte[] data = new byte[entryCount * entrySize];
			mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(tableOff), data);
			var br = ByteBuffer.wrap(data);

			for (int i = 0; i < entryCount; i++) {
				br.position(i * entrySize);
				br.getInt();
				int vrom = br.getInt();
				br.getInt();// vrom end
				long vram = br.getInt() & 0xFFFFFFFFl;

				Log.info(String.format("current ovl entry : VROM=0x%08X, virtStart=0x%08X", vrom, vram));
				if (vram != 0)
					LoadOvl("GameState_" + i, vram, vram, new Zelda64Overlay(mGame.GetFile(vrom).Data));
			}

		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}
	}

	private void LoadActorOvlTable() {
		try {
			long tableOff = Zelda64CodeInfo.CODE_INFO_TABLE.get(mGame.mVersion).actorOvlTable;
			if (tableOff == -1)
				return;

			int entrySize = 0x20;
			int entryCount = mGame.IsOot() ? 471 : mGame.IsMm() ? 690 : 0;

			byte[] data = new byte[entryCount * entrySize];
			mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(tableOff), data);
			var br = ByteBuffer.wrap(data);

			for (int i = 0; i < entryCount; i++) {
				br.position(i * entrySize);
				int vrom = br.getInt();
				br.getInt(); // vrom end
				long vram = br.getInt() & 0xFFFFFFFFl;
				br.getInt(); // vram end
				br.getInt();
				br.getInt();
				long namePtr = br.getInt() & 0xFFFFFFFFl;
				String name = (namePtr == 0) ? ("Actor_" + i) : readString(namePtr);

				if (vram != 0)
					LoadOvl(name, vram, vram, new Zelda64Overlay(mGame.GetFile(vrom).Data));
			}
		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}

	}

	private void LoadEffectSS2OvlTable() {
		try {
			long tableOff = Zelda64CodeInfo.CODE_INFO_TABLE.get(mGame.mVersion).effectSS2OvlTable;
			if (tableOff == -1)
				return;

			int entrySize = 0x1C;
			int entryCount = mGame.IsOot() ? 37 : mGame.IsMm() ? 39 : 0;

			byte[] data = new byte[entryCount * entrySize];
			mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(tableOff), data);
			var br = ByteBuffer.wrap(data);

			for (int i = 0; i < entryCount; i++) {
				br.position(i * entrySize);
				int vrom = br.getInt();
				br.getInt(); // vrom end
				long vram = br.getInt() & 0xFFFFFFFFl;
				br.getInt(); // vram end
				if (vram != 0)
					LoadOvl("EffectSS2_" + i, vram, vram, new Zelda64Overlay(mGame.GetFile(vrom).Data));
			}
		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}

	}

	private void LoadKaleidoMgrOvlTable() {
		try {
			long addr = Zelda64CodeInfo.CODE_INFO_TABLE.get(mGame.mVersion).kaleidoMgrOvlTable;
			if (addr == -1)
				return;
			byte[] data = new byte[2 * 0x1C];
			mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(addr), data);
			var br = ByteBuffer.wrap(data);

			for (int i = 0; i < 2; i++) {

				br.getInt(); // dst
				int vrom = br.getInt();
				br.getInt(); // vrom end
				long vram = br.getInt() & 0xFFFFFFFFl;
				br.getInt(); // vram end
				br.getInt(); // diff between ram and vram
				long namePtr = br.getInt() & 0xFFFFFFFFl;
				String name = (namePtr == 0) ? ("KaleidoMgrOvl_" + i) : readString(namePtr);
				if (vram != 0)
					LoadOvl(name, vram, vram, new Zelda64Overlay(mGame.GetFile(vrom).Data));
			}

		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}
	}

	private void LoadMapMarkDataOvl() {
		try {
			long addr = Zelda64CodeInfo.CODE_INFO_TABLE.get(mGame.mVersion).mapMarkDataOvlInfo;
			if (addr == -1)
				return;
			byte[] data = new byte[0x18];
			mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(addr), data);
			var br = ByteBuffer.wrap(data);

			br.getInt(); // dst
			int vrom = br.getInt();
			br.getInt(); // vrom end
			long vram = br.getInt() & 0xFFFFFFFFl;
			br.getInt(); // vram end
			if (vram != 0)
				LoadOvl("map_mark_data", vram, vram, new Zelda64Overlay(mGame.GetFile(vrom).Data));

		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}
	}

	private void LoadTransitionEffectOvlTable() {
		try {
			long tableOff = Zelda64CodeInfo.CODE_INFO_TABLE.get(mGame.mVersion).transitionEffectOvlTable;
			if (tableOff == -1)
				return;

			int entrySize = 0x1C;
			int entryCount = 7;

			byte[] data = new byte[entryCount * entrySize];
			mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(tableOff), data);
			var br = ByteBuffer.wrap(data);

			for (int i = 0; i < entryCount; i++) {
				br.position(i * entrySize);
				br.getInt();
				long vram = br.getInt() & 0xFFFFFFFFl;
				br.getInt(); // vram end
				int vrom = br.getInt();
				br.getInt(); // vrom end
				br.getInt();
				br.getInt();
				if (vram != 0)
					LoadOvl("TransitionEffOvl_" + i, vram, vram, new Zelda64Overlay(mGame.GetFile(vrom).Data));
			}
		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}

	}

	private String readString(long addr) {

		String str = "";
		try {
			char c = 0;
			do {
				c = (char) mApi.getCurrentProgram().getMemory().getByte(mApi.toAddr(addr));
				if (c != 0)
					str += c;
				addr++;
			} while (c != 0);
		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}
		return str;
	}

	private void LoadOvl(String name, long dst, long virtStart, Zelda64Overlay ovl) {
		Log.info(String.format("creating %s", name));

		// isn't really required since in our case dst == virtStart but whatever
		ovl.PerformRelocation(dst, virtStart);

		CreateSegment(name, dst, ovl.mRawData, new MemPerm("RWX"), false);
		if (ovl.mBssSize != 0)
			CreateEmptySegment(name + ".bss", dst + ovl.mRawData.length, dst + ovl.mRawData.length + ovl.mBssSize - 1,
					new MemPerm("RWX"), false);
		var addr = mApi.toAddr(dst);
		try {

			mApi.createData(addr.add(ovl.mRelaInfoOff), new Zelda64OvlRelaInfo().toDataType());
			mApi.createData(addr.add(ovl.mRelaInfoOff).add(0x14),
					new ArrayDataType(StructConverter.DWORD, ovl.mEntries.length, 4));
		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}
	}

	private void CreateData(String name, long addr, DataType type) throws Exception {
		mApi.createData(mApi.toAddr(addr), type);
		mApi.createLabel(mApi.toAddr(addr), name, true);
	}

	private void CreateSegment(String name, long start, byte[] data, MemPerm perm, boolean overlay) {
		try {
			MemoryBlock block = mApi.createMemoryBlock(name, mApi.toAddr(start), data, overlay);
			block.setPermissions(perm.R, perm.W, perm.X);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void CreateEmptySegment(String name, long start, long end, MemPerm perm, boolean overlay) {
		try {
			MemoryBlock block = mApi.getCurrentProgram().getMemory().createUninitializedBlock(name, mApi.toAddr(start),
					(end + 1 - start), overlay);
			block.setPermissions(perm.R, perm.W, perm.X);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void addHeaderInfo(Zelda64Game game) {
		var props = mApi.getCurrentProgram().getOptions(Program.PROGRAM_INFO);
		N64Rom rom = game.mRom;
		N64CheckSum sum = new N64CheckSum(rom, 6105);
		props.setString("N64 ClockRate",
				((rom.getClockRate() == 0) ? "Default" : String.format("%dHz", rom.getClockRate())));
		props.setString("N64 EntryPoint", String.format("%08X", rom.getEntryPoint()));
		props.setString("N64 ReleaseOffset", String.format("%08X", rom.getReleaseOffset()));
		props.setString("N64 CRC1",
				String.format("%08X", rom.getCRC1()) + (sum.getCRC1() == rom.getCRC1() ? " (VALID)" : " (INVALID)"));
		props.setString("N64 CRC2",
				String.format("%08X", rom.getCRC2()) + (sum.getCRC2() == rom.getCRC2() ? " (VALID)" : " (INVALID)"));
		props.setString("N64 Name", rom.getName());
		props.setString("N64 Game Code", rom.getGameCode());
		props.setString("N64 Mask ROM Version", String.format("%02X", rom.getVersion()));
		props.setString("Zelda 64 Build",
				String.format("%s (%s)", game.GetVersionLongName(), game.mVersion.GetBuildName()));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void postLoadProgramFixups(List<Program> loadedPrograms, DomainFolder folder, List<Option> options,
			MessageLog messageLog, TaskMonitor monitor) throws CancelledException, IOException {
		super.postLoadProgramFixups(loadedPrograms, folder, options, messageLog, monitor);
	}
}

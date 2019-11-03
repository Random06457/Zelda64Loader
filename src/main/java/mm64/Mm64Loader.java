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
package mm64;

import mm64.Mm64Struct.*;
import mm64.N64Struct.OsBootConfig;

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


public class Mm64Loader extends AbstractLibrarySupportLoader
{
	FlatProgramAPI mApi;
	Mm64Game mGame;
	
	
	@Override
	public String getName() {
		return "Majora's Mask 64 Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException
	{
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		try
		{
			new Mm64Game(provider.getInputStream(0).readAllBytes(), false, null);
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("MIPS:BE:64:64-32addr", "o32"), true));
		}
		catch(Exception e)
		{
			
		}
		
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException
	{
		byte[] data = provider.getInputStream(0).readAllBytes();
		
		try {
			mGame = new Mm64Game(data, true, monitor);
		} catch (Exception e) {
			e.printStackTrace();
			mGame = null;
			throw new CancelledException(e.getMessage());
		}
		N64Rom rom = mGame.mRom;

        mApi = new FlatProgramAPI(program, monitor);
		addHeaderInfo(mGame);        
        
        CreateEmptySegment("PIF", 				0x1FC00000, 0x1FC007C7, new MemPerm("RW-"), false);
        CreateEmptySegment("RDRAM", 			0xA3F00000, 0xA3F00027, new MemPerm("RW-"), false);
        CreateEmptySegment("SP_DMEM", 			0xA4000000, 0xA4000FFF, new MemPerm("RW-"), false);
        CreateEmptySegment("SP_IMEM", 			0xA4001000, 0xA4001FFF, new MemPerm("RW-"), false);
        CreateEmptySegment("SP", 				0xA4040000, 0xA404001F, new MemPerm("RW-"), false);
        CreateEmptySegment("SP_PC", 			0xA4080000, 0xA4080007, new MemPerm("RW-"), false);
        CreateEmptySegment("DPC", 				0xA4100000, 0xA410001F, new MemPerm("RW-"), false);
        CreateEmptySegment("DPS", 				0xA4200000, 0xA420000F, new MemPerm("RW-"), false);
        CreateEmptySegment("MI", 				0xA4300000, 0xA430000F, new MemPerm("RW-"), false);
        CreateEmptySegment("VI", 				0xA4400000, 0xA4400037, new MemPerm("RW-"), false);
        CreateEmptySegment("AI", 				0xA4500000, 0xA4500017, new MemPerm("RW-"), false);
        CreateEmptySegment("PI", 				0xA4600000, 0xA4600033, new MemPerm("RW-"), false);
        CreateEmptySegment("RI", 				0xA4700000, 0xA470001F, new MemPerm("RW-"), false);
        CreateEmptySegment("SI", 				0xA4800000, 0xA480001B, new MemPerm("RW-"), false);
        CreateEmptySegment("CART_DOM2_ADDR1",	0xA5000000, 0xA507FFFF, new MemPerm("RW-"), false);
        CreateEmptySegment("CART_DOM1_ADDR1",	0xA6000000, 0xA7FFFFFF, new MemPerm("RW-"), false);
        CreateEmptySegment("CART_DOM2_ADDR2",	0xA8000000, 0xAFFFFFFF, new MemPerm("RW-"), false);
        CreateEmptySegment("CART_DOM1_ADDR2",	0xB0000000, 0xB8000803, new MemPerm("RW-"), false);
        CreateEmptySegment("PIF_virt",			0xBFC00000, 0xBFC007c7, new MemPerm("RW-"), false); 
        
        
        int entrypoint = rom.getEntryPoint()+0x60;
        CreateEmptySegment("RAM0", 0x80000000, entrypoint-1, new MemPerm("RWX"), false);
        byte[] boot = mGame.GetFile(0x00001060).Data; //should be constant
        CreateSegment("boot", entrypoint, boot, new MemPerm("RWX"), false);
        
        int codeVrom = mGame.getCodeVrom();
        if (codeVrom != -1)
        {
        	long codeDst = mGame.getCodeDst();
            byte[] code = mGame.GetFile(codeVrom).Data;
            
            CreateEmptySegment("RAM1", entrypoint+boot.length, codeDst-1, new MemPerm("RWX"), false);
            CreateSegment("code", codeDst, code, new MemPerm("RWX"), false);
            CreateEmptySegment("RAM2", codeDst+code.length, 0x807FFFFF, new MemPerm("RW-"), false);
            LoadOvlTable();
        }
        
        try
        {
            mApi.addEntryPoint(mApi.toAddr(entrypoint));
            mApi.createFunction(mApi.toAddr(entrypoint), "entrypoint");
            
            CreateData("g_bootCfg", 0x80000300, new OsBootConfig().toDataType());
        }
        catch (Exception e)
        {
        	e.printStackTrace();
        }

	}
	
	private void LoadOvlTable()
	{
		try
		{
			long tableCountOff = mGame.getOvlEntryCountAddr();
			
			if (tableCountOff == -1)
				return;
			
			int entrySize = 0x30;
			
			byte[] tmp = new byte[4];
			mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(tableCountOff), tmp);
	        int entryCount = ByteBuffer.wrap(tmp).getInt();
	        
			Log.info(String.format("Found %d ovl entries", entryCount));
			
			long startOff = (tableCountOff - entryCount*entrySize) & 0xFFFFFFFFl;
			Log.info(String.format("Ovl table : 0x%08X", startOff));
			tmp = new byte[entryCount*entrySize];
			mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(startOff), tmp);
			var br = ByteBuffer.wrap(tmp);
			
			for (int i = 0; i < entryCount; i++)
			{
				br.position(i*entrySize);
	            br.getInt();
	            int curVrom = br.getInt();
	            br.getInt();//vrom end
	            long virtStart = br.getInt() & 0xFFFFFFFFl;

            	Log.info(String.format("current ovl entry : VROM=0x%08X, virtStart=0x%08X", curVrom, virtStart));
            	if (virtStart != 0)
            		/*
            		 * The destination address is normally somewhere on a heap (at 80379d00-80780000 in ver. Europe 1.1)
            		 * but it doesn't really matter which value we choose since each entry has a relocation table.
            		 * We could calculate the loading address like this : dst = heapEnd - filesize
            		 * */
                	LoadOvl("ovl" + i, virtStart, virtStart, new Mm64Overlay(mGame.GetFile(curVrom).Data));
			}
			
			
		}
		catch(Exception e)
		{
        	e.printStackTrace();
        	Msg.error(this, e.getMessage());
		}
	}
	
	private void LoadOvl(String name, long dst, long virtStart, Mm64Overlay ovl)
	{
		Log.info(String.format("creating %s", name));
		
		//isn't really required since in our case dst == virtStart but whatever
		ovl.PerformRelocation(dst, virtStart);
		byte[] data = new byte[(int)(ovl.mRawData.length + ovl.mBssSize)];
		ByteBuffer buff = ByteBuffer.wrap(data);
		buff.put(ovl.mRawData);
		
		CreateSegment(name, dst, data, new MemPerm("RWX"), true);
		var addr = mApi.toAddr(String.format("%s::0x%08x", name, dst));
		try
		{
			mApi.createLabel(addr, name + ".text", true);
			mApi.createLabel(addr.add(ovl.mTextSize), name + ".data", true);
			mApi.createLabel(addr.add(ovl.mTextSize).add(ovl.mDataSize), name + ".rodata", true);
			mApi.createLabel(addr.add(ovl.mTextSize).add(ovl.mDataSize).add(ovl.mRodataSize), name + ".bss", true);

			mApi.createData(addr.add(ovl.mRelaInfoOff), new Mm64OvlRelaInfo().toDataType());
			mApi.createData(addr.add(ovl.mRelaInfoOff).add(0x14), new ArrayDataType(StructConverter.DWORD, ovl.mEntries.length, 4));
		}
		catch(Exception e)
		{
        	e.printStackTrace();
        	Msg.error(this, e.getMessage());
		}
	}
	
	
	private void CreateData(String name, long addr, DataType type) throws Exception
	{
		mApi.createData(mApi.toAddr(addr), type);
		mApi.createLabel(mApi.toAddr(addr), name, true);
	}
	
	private void CreateSegment(String name, long start, byte[] data, MemPerm perm, boolean overlay)
	{
		try {
			MemoryBlock block = mApi.createMemoryBlock(name, mApi.toAddr(start), data, overlay);
			block.setPermissions(perm.R, perm.W, perm.X);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void CreateEmptySegment(String name, long start, long end, MemPerm perm, boolean overlay)
	{
		try {
			MemoryBlock block = mApi.getCurrentProgram().getMemory().createUninitializedBlock(name, mApi.toAddr(start), (end+1-start), overlay);
			block.setPermissions(perm.R, perm.W, perm.X);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void addHeaderInfo(Mm64Game game)
	{
		var props = mApi.getCurrentProgram().getOptions(Program.PROGRAM_INFO);
		N64Rom rom = game.mRom;
		N64CheckSum sum = new N64CheckSum(rom, 6105);
		props.setString("N64 ClockRate", ((rom.getClockRate() == 0)? "Default" : String.format("%dHz", rom.getClockRate())));
		props.setString("N64 EntryPoint", String.format("%08X", rom.getEntryPoint()));
		props.setString("N64 ReleaseOffset", String.format("%08X", rom.getReleaseOffset()));
		props.setString("N64 CRC1", String.format("%08X", rom.getCRC1()) + (sum.getCRC1() == rom.getCRC1() ? " (VALID)" : " (INVALID)"));
		props.setString("N64 CRC2", String.format("%08X", rom.getCRC2()) + (sum.getCRC2() == rom.getCRC2() ? " (VALID)" : " (INVALID)"));
		props.setString("N64 Name", rom.getName());
		props.setString("N64 Game Code", rom.getGameCode());
		props.setString("N64 Mask ROM Version", String.format("%02X", rom.getVersion()));
		props.setString("MM64 Build", String.format("%s (%s)", game.mVersion, game.mVersion.GetBuildName()));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject, boolean isLoadIntoProgram)
	{
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program)
	{
		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	@Override
	protected void postLoadProgramFixups(List<Program> loadedPrograms, DomainFolder folder, List<Option> options, MessageLog messageLog, TaskMonitor monitor) throws CancelledException, IOException
	{
		super.postLoadProgramFixups(loadedPrograms, folder, options, messageLog, monitor);
	}
}

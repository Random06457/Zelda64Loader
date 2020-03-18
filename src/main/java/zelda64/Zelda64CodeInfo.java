package zelda64;

import java.util.HashMap;
import java.util.Map;

public class Zelda64CodeInfo {
	public long codeDst;
	public long codeVrom;
	public long actorOvlTable;
	public long gameStateOvlTable;
	public long effectSS2OvlTable;
	public long kaleidoMgrOvlTable;
	public long mapMarkDataOvlInfo; // specific to oot
	public long transitionEffectOvlTable; // specific to mm

	public Zelda64CodeInfo(long codeDst, long codeVrom, long actorOvlTable, long gameStateOvlTable,
			long effectSS2OvlTable, long kaleidoMgrOvlTable, long mapMarkDataOvlInfo, long transitionEffectOvlTable) {
		this.codeDst = codeDst;
		this.codeVrom = codeVrom;
		this.actorOvlTable = actorOvlTable;
		this.gameStateOvlTable = gameStateOvlTable;
		this.effectSS2OvlTable = effectSS2OvlTable;
		this.kaleidoMgrOvlTable = kaleidoMgrOvlTable;
		this.mapMarkDataOvlInfo = mapMarkDataOvlInfo;
		this.transitionEffectOvlTable = transitionEffectOvlTable;
	}

	public static final Map<Zelda64Version, Zelda64CodeInfo> CODE_INFO_TABLE = new HashMap<Zelda64Version, Zelda64CodeInfo>() {
		{
			// Ocarina Of Time
			put(Zelda64Version.OotEurope10, new Zelda64CodeInfo(0x800116e0, 0xa89000, 0x800e6480, 0x800ef290,
					0x800e5b90, 0x800fc3e0, 0x800efb48, -1));
			put(Zelda64Version.OotEurope11, new Zelda64CodeInfo(0x800116e0, 0xa89000, 0x800e64c0, 0x800ef2d0,
					0x800e5bd0, 0x800fc420, 0x800efb88, -1));
			put(Zelda64Version.OotEuropeGC, new Zelda64CodeInfo(0x80010f00, 0xa88000, 0x800e53a0, 0x800ee1b0,
					0x800e4ab0, 0x800fb300, 0x800eea68, -1));
			put(Zelda64Version.OotEuropeMq, new Zelda64CodeInfo(0x80010f00, 0xa88000, 0x800e5380, 0x800ee190,
					0x800e4a90, 0x800fb2e0, 0x800eea48, -1));
			put(Zelda64Version.OotEuropeMqDbg, new Zelda64CodeInfo(0x8001CE60, 0xa94000, 0x801162a0, 0x8011f830,
					0x801159b0, 0x8012d1a0, 0x801200f8, -1));
			put(Zelda64Version.OotJPUS10, new Zelda64CodeInfo(0x800110a0, 0xa87000, 0x800e8530, 0x800f1340, 0x800e7c40,
					0x800fe480, 0x800f1bf8, -1));
			put(Zelda64Version.OotJPUS11, new Zelda64CodeInfo(0x800110a0, 0xa87000, 0x800e86f0, 0x800f1500, 0x800e7e00,
					0x800fe640, 0x800f1db8, -1));
			put(Zelda64Version.OotJPUS12, new Zelda64CodeInfo(0x800116e0, 0xa87000, 0x800e8b70, 0x800f1980, 0x800e8280,
					0x800fead0, 0x800f2238, -1));
			put(Zelda64Version.OotJapanGC, new Zelda64CodeInfo(0x80010ee0, 0xa86000, 0x800e7a40, 0x800f0850, 0x800e7150,
					0x800fd9a0, 0x800f1108, -1));
			put(Zelda64Version.OotJapanGcZeldaCollection, new Zelda64CodeInfo(0x80010ee0, 0xa86000, 0x800e7a20,
					0x800f0830, 0x800e7130, 0x800fd980, 0x800f10e8, -1));
			put(Zelda64Version.OotJapanMq, new Zelda64CodeInfo(0x80010ee0, 0xa86000, 0x800e7a20, 0x800f0830, 0x800e7130,
					0x800fd980, 0x800f10e8, -1));
			put(Zelda64Version.OotUSAGC, new Zelda64CodeInfo(0x80010ee0, 0xa86000, 0x800e7a20, 0x800f0830, 0x800e7130,
					0x800fd980, 0x800f10e8, -1));
			put(Zelda64Version.OotUSAMq, new Zelda64CodeInfo(0x80010ee0, 0xa86000, 0x800e7a00, 0x800f0810, 0x800e7110,
					0x800fd960, 0x800f10c8, -1));
			// Majora's Mask
			put(Zelda64Version.MmEurope10, new Zelda64CodeInfo(0x800a5d60, 0xc8a000, 0x801af760, 0x801BE0A0, 0x801aefc0,
					0x801c90b0, -1, 0x801c90f0));
			put(Zelda64Version.MmEurope11, new Zelda64CodeInfo(0x800a5fe0, 0xc8a000, 0x801afb00, 0x801BE440, 0x801af360,
					0x801c9450, -1, 0x801c9490));
			put(Zelda64Version.MmEurope11Debug, new Zelda64CodeInfo(0x800b6ac0, 0xc95000, 0x801f7510, 0x80206820,
					0x801f69e0, 0x80212080, -1, 0x802120c0));
			put(Zelda64Version.MmJapan10, new Zelda64CodeInfo(0x800a76a0, 0xb5f000, 0x801a9e60, 0x801B87A0, 0x801a9330,
					0x801cb330, -1, 0x801cb370));
			put(Zelda64Version.MmJapan11, new Zelda64CodeInfo(0x800a75e0, 0xb5f000, 0x801aa0a0, 0x801B89E0, 0x801a9570,
					0x801cb540, -1, 0x801cb580));
			put(Zelda64Version.MmUSA10, new Zelda64CodeInfo(0x800a5ac0, 0xb3c000, 0x801aefd0, 0x801BD910, 0x801ae4a0,
					0x801d0b70, -1, 0x801d0bb0));
			put(Zelda64Version.MmUSADemo, new Zelda64CodeInfo(0x800a6120, 0xb3d000, 0x801ae830, 0x801BD170, 0x801add00,
					0x801d0380, -1, 0x801d03c0));
		}
	};
}

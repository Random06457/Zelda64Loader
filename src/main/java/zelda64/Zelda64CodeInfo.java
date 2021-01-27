package zelda64;

import java.util.HashMap;
import java.util.Map;

public class Zelda64CodeInfo {
    public long mBootData;
    public long mBootRodata;
    public long mCodeText;
    public long mCodeData;
    public long mCodeRodata;
    public long mCodeVrom;
    public long mActorOvlTable;
    public long mGameStateOvlTable;
    public long mEffectSS2OvlTable;
    public long mKaleidoMgrOvlTable;
    public long mMapMarkDataOvlInfo; // specific to oot
    public long mFbDemoOvlTable; // specific to mm

    public Zelda64CodeInfo(long bootData, long bootRodata, long codeText, long codeData, long codeRodata, long codeVrom,
            long actorOvlTable, long gameStateOvlTable, long effectSS2OvlTable, long kaleidoMgrOvlTable,
            long mapMarkDataOvlInfo, long fbDemoOvlTable) {
        this.mBootData = bootData == -1 ? -1 : bootData & 0xFFFFFFFFl;
        this.mBootRodata = bootRodata == -1 ? -1 : bootRodata & 0xFFFFFFFFl;
        this.mCodeText = codeText == -1 ? -1 : codeText & 0xFFFFFFFFl;
        this.mCodeData = codeData == -1 ? -1 : codeData & 0xFFFFFFFFl;
        this.mCodeRodata = codeRodata == -1 ? -1 : codeRodata & 0xFFFFFFFFl;
        this.mCodeVrom = codeVrom == -1 ? -1 : codeVrom & 0xFFFFFFFFl;
        this.mActorOvlTable = actorOvlTable == -1 ? -1 : actorOvlTable & 0xFFFFFFFFl;
        this.mGameStateOvlTable = gameStateOvlTable == -1 ? -1 : gameStateOvlTable & 0xFFFFFFFFl;
        this.mEffectSS2OvlTable = effectSS2OvlTable == -1 ? -1 : effectSS2OvlTable & 0xFFFFFFFFl;
        this.mKaleidoMgrOvlTable = kaleidoMgrOvlTable == -1 ? -1 : kaleidoMgrOvlTable & 0xFFFFFFFFl;
        this.mMapMarkDataOvlInfo = mapMarkDataOvlInfo == -1 ? -1 : mapMarkDataOvlInfo & 0xFFFFFFFFl;
        this.mFbDemoOvlTable = fbDemoOvlTable == -1 ? -1 : fbDemoOvlTable & 0xFFFFFFFFl;
    }

    public static final Map<Zelda64Version, Zelda64CodeInfo> TABLE = new HashMap<Zelda64Version, Zelda64CodeInfo>() {
        {
            // Ocarina Of Time
            put(Zelda64Version.OotEurope10, new Zelda64CodeInfo(0x800066e0, 0x80006a70, 0x800116e0, 0x800e5600,
                    0x80103cb0, 0xa89000, 0x800e6480, 0x800ef290, 0x800e5b90, 0x800fc3e0, 0x800efb48, -1));
            put(Zelda64Version.OotEurope11, new Zelda64CodeInfo(0x800066e0, 0x80006a70, 0x800116e0, 0x800e5640,
                    0x80103cf0, 0xa89000, 0x800e64c0, 0x800ef2d0, 0x800e5bd0, 0x800fc420, 0x800efb88, -1));
            put(Zelda64Version.OotEuropeGC, new Zelda64CodeInfo(0x800060b0, 0x800063a0, 0x80010f00, 0x800e4520,
                    0x801027a0, 0xa88000, 0x800e53a0, 0x800ee1b0, 0x800e4ab0, 0x800fb300, 0x800eea68, -1));
            put(Zelda64Version.OotEuropeGCMq, new Zelda64CodeInfo(0x800060b0, 0x800063a0, 0x80010f00, 0x800e4500,
                    0x80102780, 0xa88000, 0x800e5380, 0x800ee190, 0x800e4a90, 0x800fb2e0, 0x800eea48, -1));
            put(Zelda64Version.OotEuropeGCMqDbg, new Zelda64CodeInfo(0x80009410, 0x8000afc0, 0x8001CE60, 0x80115420,
                    0x80134d30, 0xa94000, 0x801162a0, 0x8011f830, 0x801159b0, 0x8012d1a0, 0x801200f8, -1));
            put(Zelda64Version.OotEuropeGCDbg, new Zelda64CodeInfo(0x80009410, 0x8000afc0, 0x8001ce60, 0x80115440,
                    0x80134d50, 0xa94000, 0x801162c0, 0x8011f850, 0x801159d0, 0x8012d1c0, 0x80120118, -1));
        	put(Zelda64Version.OotJPUS09, new Zelda64CodeInfo(0x80006230, 0x80006550, 0x800110a0, 0x800e74c0,
        			0x80105b50, 0xa87000, 0x800e8320, 0x800f1130, 0x800e7a30, 0x800fe270, 0x800f19e8, -1));
            put(Zelda64Version.OotJPUS10, new Zelda64CodeInfo(0x80006230, 0x80006550, 0x800110a0, 0x800e76b0,
                    0x80105d60, 0xa87000, 0x800e8530, 0x800f1340, 0x800e7c40, 0x800fe480, 0x800f1bf8, -1));
            put(Zelda64Version.OotJPUS11, new Zelda64CodeInfo(0x80006230, 0x80006550, 0x800110a0, 0x800e7870,
                    0x80105f20, 0xa87000, 0x800e86f0, 0x800f1500, 0x800e7e00, 0x800fe640, 0x800f1db8, -1));
            put(Zelda64Version.OotJPUS12, new Zelda64CodeInfo(0x80006740, 0x80006a80, 0x800116e0, 0x800e7cf0,
                    0x801063f0, 0xa87000, 0x800e8b70, 0x800f1980, 0x800e8280, 0x800fead0, 0x800f2238, -1));
            put(Zelda64Version.OotJapanGC, new Zelda64CodeInfo(0x800060b0, 0x800063a0, 0x80010ee0, 0x800e6bc0,
                    0x80104e40, 0xa86000, 0x800e7a40, 0x800f0850, 0x800e7150, 0x800fd9a0, 0x800f1108, -1));
            put(Zelda64Version.OotJapanGcZeldaCollection, new Zelda64CodeInfo(0x800060b0, 0x800063a0, 0x80010ee0,
                    0x800e6ba0, 0x80104e20, 0xa86000, 0x800e7a20, 0x800f0830, 0x800e7130, 0x800fd980, 0x800f10e8, -1));
            put(Zelda64Version.OotJapanGCMq, new Zelda64CodeInfo(0x800060b0, 0x800063a0, 0x80010ee0, 0x800e6ba0,
                    0x80104e20, 0xa86000, 0x800e7a20, 0x800f0830, 0x800e7130, 0x800fd980, 0x800f10e8, -1));
            put(Zelda64Version.OotUSAGC, new Zelda64CodeInfo(0x800060b0, 0x800063a0, 0x80010ee0, 0x800e6ba0, 0x80104e20,
                    0xa86000, 0x800e7a20, 0x800f0830, 0x800e7130, 0x800fd980, 0x800f10e8, -1));
            put(Zelda64Version.OotUSAGCMq, new Zelda64CodeInfo(0x800060b0, 0x800063a0, 0x80010ee0, 0x800e6b80,
                    0x80104e00, 0xa86000, 0x800e7a00, 0x800f0810, 0x800e7110, 0x800fd960, 0x800f10c8, -1));
            // Majora's Mask
            // TODO: support GC roms
            put(Zelda64Version.MmEurope10, new Zelda64CodeInfo(0x80096b80, 0x800982e0, 0x800a5d60, 0x801ae980,
                    0x801d4380, 0xc8a000, 0x801af760, 0x801BE0A0, 0x801aefc0, 0x801c90b0, -1, 0x801c90f0));
            put(Zelda64Version.MmEurope11, new Zelda64CodeInfo(0x80096cc0, 0x80098420, 0x800a5fe0, 0x801aed20,
                    0x801d4720, 0xc8a000, 0x801afb00, 0x801BE440, 0x801af360, 0x801c9450, -1, 0x801c9490));
            put(Zelda64Version.MmEurope11Debug, new Zelda64CodeInfo(0x8009f630, 0x800a0f10, 0x800b6ac0, 0x801f63a0,
                    0x8021e110, 0xc95000, 0x801f7510, 0x80206820, 0x801f69e0, 0x80212080, -1, 0x802120c0));
            put(Zelda64Version.MmJapan10, new Zelda64CodeInfo(0x80097b00, 0x800991c0, 0x800a76a0, 0x801a8cf0,
                    0x801d6520, 0xb5f000, 0x801a9e60, 0x801B87A0, 0x801a9330, 0x801cb330, -1, 0x801cb370));
            put(Zelda64Version.MmJapan11, new Zelda64CodeInfo(0x80097a40, 0x80099100, 0x800a75e0, 0x801a8f30,
                    0x801d6730, 0xb5f000, 0x801aa0a0, 0x801B89E0, 0x801a9570, 0x801cb540, -1, 0x801cb580));
            put(Zelda64Version.MmUSA10, new Zelda64CodeInfo(0x80096b20, 0x80098190, 0x800a5ac0, 0x801ade60, 0x801dbdf0,
                    0xb3c000, 0x801aefd0, 0x801BD910, 0x801ae4a0, 0x801d0b70, -1, 0x801d0bb0));
            put(Zelda64Version.MmUSADemo, new Zelda64CodeInfo(0x80097080, 0x80098700, 0x800a6120, 0x801ad6c0,
                    0x801db600, 0xb3d000, 0x801ae830, 0x801BD170, 0x801add00, 0x801d0380, -1, 0x801d03c0));
        }
    };
}

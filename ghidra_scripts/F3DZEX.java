import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class F3DZEX {

    private static long sftr(long w, int shift, int bits) {
        if (w == -1)
            return -1;
        return (w >> shift) & ((1l << bits) - 1);
    }

    private static String sftrStr(long w, int shift, int bits) {
        return w == -1 ? "?" : Long.toString(sftr(w, shift, bits));
    }

    private static String sftrStr(String format, long w, int shift, int bits) {
        return w == -1 ? "?" : String.format(format, sftr(w, shift, bits));
    }

    private static String fp(long w, int shift, int intBits, int fracBits, boolean signed) {
        if (w == -1)
            return "?";
        List<String> parts = new ArrayList<String>();
        int totalBits = intBits + fracBits + (signed ? 1 : 0);
        long raw = sftr(w, shift, totalBits);

        boolean signBit = signed && ((raw >> (intBits + fracBits)) & 1) == 1;
        if (signBit)
            parts.add(String.format("(1<<%d)", (intBits + fracBits)));

        long intPart = (raw >> fracBits) & ((1 << intBits) - 1);
        if (intPart != 0)
            parts.add(String.format("(%d<<%d)", intPart, (fracBits)));

        long fracPart = raw & ((1 << fracBits) - 1);
        if (fracPart != 0)
            parts.add(String.format("%d", fracPart));

        if (parts.size() == 0)
            return "0";

        return parts.stream().collect(Collectors.joining("|"));
    }

    private static String ParseTile(long tile) {
        if (tile == -1)
            return "?";
        return tile == 7 ? "G_TX_LOADTILE" : (tile == 0) ? "G_TX_RENDERTILE" : (tile + "");
    }

    private static String ParseVtxWhere(long where) {
        if (where == -1)
            return "?";
        switch ((int) where) {
        case 0x10:
            return "G_MWO_POINT_RGBA";
        case 0x14:
            return "G_MWO_POINT_ST";
        case 0x18:
            return "G_MWO_POINT_XYSCREEN";
        case 0x1C:
            return "G_MWO_POINT_ZSCREEN";
        default:
            return String.format("0x%08X", where);
        }
    }

    private static String ParseWordIndex(long index) {
        if (index == -1)
            return "?";
        switch ((int) index) {
        case 0x00:
            return "G_MW_MATRIX";
        case 0x02:
            return "G_MW_NUMLIGHT";
        case 0x04:
            return "G_MW_CLIP";
        case 0x06:
            return "G_MW_SEGMENT";
        case 0x08:
            return "G_MW_FOG";
        case 0x0A:
            return "G_MW_LIGHTCOL";
        case 0x0C:
            return "G_MW_FORCEMTX";
        case 0x0E:
            return "G_MW_PERSPNORM";
        default:
            return String.format("0x%X", index);
        }
    }

    private static String ParseMtxFlag(long flag) {
        if (flag == -1)
            return "?";
        return ((flag & 1) != 0 ? "G_MTX_PUSH" : "G_MTX_NOPUSH") + "|" + ((flag & 2) != 0 ? "G_MTX_LOAD" : "G_MTX_MUL")
                + "|" + ((flag & 4) != 0 ? "G_MTX_PROJECTION" : "G_MTX_MODELVIEW");
    }

    private static String ParseImFmt(long fmt) {
        if (fmt == -1)
            return "?";
        switch ((int) fmt) {
        case 0:
            return "G_IM_FMT_RGBA";
        case 1:
            return "G_IM_FMT_YUV";
        case 2:
            return "G_IM_FMT_CI";
        case 3:
            return "G_IM_FMT_IA";
        case 4:
            return "G_IM_FMT_I";
        default:
            return Long.toString(fmt);
        }
    }

    private static String ParseImSiz(long siz) {
        if (siz == -1)
            return "?";
        switch ((int) siz) {
        case 0:
            return "G_IM_SIZ_4b";
        case 1:
            return "G_IM_SIZ_8b";
        case 2:
            return "G_IM_SIZ_16b";
        case 3:
            return "G_IM_SIZ_32b";
        default:
            return Long.toString(siz);
        }
    }

    private static String ParseScissorMode(long mode) {
        if (mode == -1)
            return "?";
        switch ((int) mode) {
        case 0:
            return "G_SC_NON_INTERLACE";
        case 2:
            return "G_SC_EVEN_INTERLACE";
        case 3:
            return "G_SC_ODD_INTERLACE";
        default:
            return Long.toString(mode);
        }
    }

    private static String ParseMirrorClamp(long flag) {
        if (flag == -1)
            return "?";
        return ((flag & 1) != 0 ? "G_TX_MIRROR" : "G_TX_NOMIRROR") + "|"
                + ((flag & 2) != 0 ? "G_TX_CLAMP" : "G_TX_WRAP");
    }

    // reimp of oot's code
    private static String ParseCombineColor(long value, int idx) {
        if (value == -1)
            return "?";

        switch ((int) value) {
        case 0:
            return "COMBINED";
        case 1:
            return "TEXEL0";
        case 2:
            return "TEXEL1";
        case 3:
            return "PRIMITIVE";
        case 4:
            return "SHADE";
        case 5:
            return "ENVIRONMENT";
        case 6:
            return (idx == 2) ? "CENTER" : (idx == 3) ? "SCALE" : "1";
        case 7:
            return (idx == 1) ? "NOISE" : (idx == 2) ? "K4" : (idx == 3) ? "COMBINED_ALPHA" : "0";
        default: {
            if (idx == 3) {
                switch ((int) value) {
                case 8:
                    return "TEXEL0_ALPHA";
                case 9:
                    return "TEXEL1_ALPHA";
                case 10:
                    return "PRIMITIVE_ALPHA";
                case 11:
                    return "SHADE_ALPHA";
                case 12:
                    return "ENV_ALPHA";
                case 13:
                    return "LOD_FRACTION";
                case 14:
                    return "PRIM_LOD_FRAC";
                case 15:
                    return "K5";
                default:
                    return "0";
                }
            }
            return "0";
        }
        }
    }

    // reimp of oot's code
    private static String ParseCombineAlpha(long value, int idx) {
        switch ((int) value) {
        case 0:
            return (idx == 3) ? "LOD_FRACTION" : "COMBINED";
        case 1:
            return "TEXEL0";
        case 2:
            return "TEXEL1";
        case 3:
            return "PRIMITIVE";
        case 4:
            return "SHADE";
        case 5:
            return "ENVIRONMENT";
        case 6:
            return (idx == 3) ? "PRIM_LOD_FRAC" : "1";
        case 7:
            return "0";
        default:
            return "?";
        }
    }

    private static String DisSetColor(String macro, long w1, boolean DPRGB) {
        if (w1 == -1)
            return (DPRGB) ? String.format("%s(?, ?, ?, ?)", macro) : String.format("%s(?)", macro, w1);

        return (DPRGB)
                ? String.format("%s(%d, %d, %d, %d)", macro, sftr(w1, 24, 8), sftr(w1, 16, 8), sftr(w1, 8, 8),
                        sftr(w1, 0, 8))
                : String.format("%s(0x%08X)", macro, w1);
    }

    private static String DisLoadTileGeneric(String macro, long w0, long w1) {
        String tile = ParseTile(sftr(w1, 24, 3));
        String lrs = fp(w1, 12, 10, 2, false);
        String lrt = fp(w1, 0, 10, 2, false);
        String uls = fp(w0, 12, 10, 2, false);
        String ult = fp(w0, 0, 10, 2, false);
        return String.format("%s(%s, %s, %s, %s, %s)", macro, tile, uls, ult, lrs, lrt);
    }

    private static String DisSetImage(String macro, long w0, long w1) {
        String fmt = ParseImFmt(sftr(w0, 21, 3));
        String siz = ParseImSiz(sftr(w0, 19, 2));
        long width = sftr(w0, 0, 12) + 1;
        String i = sftrStr("0x%08X", w1, 0, 32);

        return String.format("%s(%s, %s, %d, %s)", macro, fmt, siz, width, i);
    }

    public static F3DZEXOpCodeId GetOpCodeID(long w0) {
        var values = F3DZEXOpCodeId.values();
        for (int i = 0; i < values.length; i++) {
            if (((w0 >> 24) & 0xFF) == values[i].ID)
                return values[i];
        }
        return F3DZEXOpCodeId.Invalid;
    }

    public static String Disassemble(long w0, long w1, long half1, long half2) {
        if (w0 == -1)
            return "G_?";

        var id = GetOpCodeID(w0);

        switch (id) {
        case G_BRANCH_Z: {
            String newdl = sftrStr("0x%08X", half1, 0, 32);
            long vbidx = sftr(w0, 12, 12) / 5;
            String zval = sftrStr("0x%X", w0, 0, 32);
            return String.format("gsSPBranchLessZraw(%s, %d, %s)", newdl, vbidx, zval);
        }
        case G_CULLDL: {
            return (w1 == -1) ? String.format("gsSPCullDisplayList(%d, ?)", (sftr(w0, 0, 16) / 2))
                    : String.format("gsSPCullDisplayList(%d, %d)", (sftr(w0, 0, 16) / 2), (sftr(w1, 0, 16) / 2));
        }
        case G_DL: {
            String dl = sftrStr("0x%08X", w1, 0, 32);
            boolean branch = sftr(w1, 16, 8) == 1;
            return branch ? String.format("gsSPBranchList(%s)", dl) : String.format("gsSPDisplayList(%s)", dl);
        }
        case G_DMA_IO: {
            long flag = sftr(w0, 23, 1);
            long dmem = sftr(w0, 13, 10) * 8;
            long size = sftr(w0, 0, 12) + 1;
            String dram = sftrStr("0x%08X", w1, 0, 32);
            return String.format("gsSPDma_io(0x%X, 0x%X, %s, 0x%X)", flag, dmem, dram, size);
        }
        case G_ENDDL:
            return "gsSPEndDisplayList()";
        case G_FILLRECT:
            return String.format("gsDPFillRectangle(%s, %s, %s, %s)", sftrStr(w1, 14, 10), sftrStr(w1, 2, 10),
                    sftrStr(w0, 14, 10), sftrStr(w0, 2, 10));
        case G_GEOMETRYMODE: {
            long clearBits = sftr(w0, 0, 24);
            if (clearBits == 0)
                return String.format("gsSPLoadGeometryMode(%s)", sftrStr("0x%X", w0, 0, 32));
            else if (w1 == 0)
                return String.format("gsSPClearGeometryMode(0x%X)", (~clearBits) & 0xFFFFFFl);
            else if (clearBits == 0xFFFFFF)
                String.format("gsSPSetGeometryMode(%s)", sftrStr("0x%X", w0, 0, 32));
            else
                String.format("gsSPGeometryMode(0x%X, %s)", (~clearBits) & 0xFFFFFFl, sftrStr("0x%X", w0, 0, 32));
        }
        case G_LOADBLOCK: {
            String tile = ParseTile(sftr(w1, 24, 3));
            String uls = fp(w0, 12, 10, 2, false);
            String ult = fp(w0, 0, 10, 2, false);
            String lrs = sftrStr(w1, 12, 12);
            String dxt = fp(w1, 0, 1, 11, false);
            return String.format("gsDPLoadBlock(%s, %s, %s, %s, %s)", tile, uls, ult, lrs, dxt);
        }
        case G_LOADTILE:
            return DisLoadTileGeneric("gsDPLoadTile", w0, w1);
        case G_LOADTLUT: {
            String tile = ParseTile(sftr(w1, 24, 3));
            return String.format("gsDPLoadTLUTCmd(%s, %s)", tile, sftrStr(w1, 14, 10));
        }
        case G_LOAD_UCODE: {
            String dstart = sftrStr("0x%08X", half1, 0, 32);
            String dsize = sftrStr("0x%X", w0, 0, 16);
            String tstart = sftrStr("0x%08X", w0, 0, 32);
            return String.format("gsSPLoadUcodeEx(%s, %s, %s)", tstart, dstart, dsize);
        }
        case G_MODIFYVTX: {
            String where = ParseVtxWhere(sftr(w0, 16, 8));
            long vtx = sftr(w0, 0, 16) / 2;
            String value = sftrStr("0x%08X", w1, 0, 32);
            return String.format("gsSPModifyVertex(%d, %s, %s)", vtx, where, value);
        }
        case G_MOVEMEM: {
            long offset = sftr(w0, 8, 8) * 8;
            long size = ((sftr(w0, 16, 8) >> 3) + 1) * 8;
            long index = sftr(w0, 0, 8);
            String addr = sftrStr("0x%08X", w1, 0, 32);
            switch ((int) index) {
            case 8:
                return String.format("gsSPViewport(%s)", addr);
            case 14:
                return String.format("gsSPForceMatrix(%s)", addr);
            case 10: {
                switch ((int) offset) {
                case 0:
                    return String.format("gsSPLookAtX(%s)", addr);
                case 24:
                    return String.format("gsSPLookAtY(%s)", addr);
                default:
                    return String.format("gsSPLight(%s, %d)", addr, (offset - 24) / 24);
                }
            }
            default:
                return String.format("gsMoveMem(%s, %d, %d, %d)", addr, size, index, offset);
            }
        }
        case G_MOVEWORD: {
            long index = sftr(w0, 16, 8);
            long offset = sftr(w0, 0, 16);
            switch ((int) index) {
            case 6:
                return String.format("gsSPSegment(%d, %s)", offset / 4, sftrStr("0x%08X", w1, 0, 32));
            // case 4: //gsSPClipRatio
            case 2:
                return String.format("gsSPNumLights(%s)", w1 == -1 ? "?" : String.format("0x%08X", w1 / 24));
            // case 10: /gsSPLightColor
            case 8:
                return String.format("gsSPFogFactor(%s, %s)", sftrStr("0x%X", w1, 16, 16), sftrStr("0x%X", w1, 0, 16));
            case 14:
                return String.format("gsSPPerspNormalize(%s)", sftrStr("0x%X", w1, 0, 32));
            default:
                return String.format("gsMoveWd(%s, 0x%X, %s)", ParseWordIndex(index), offset,
                        sftrStr("0x%X", w1, 0, 32));
            }
        }
        case G_MTX: {
            String params = ParseMtxFlag(sftr(w0, 0, 8) ^ 1);
            String mtxaddr = sftrStr("0x%08X", w1, 0, 32);
            return String.format("gsSPMatrix(%s, %s)", mtxaddr, params);
        }
        case G_NOOP:
            return String.format("gsDPNoOpTag(%s)", sftrStr(w1, 0, 32));
        case G_POPMTX:
            return String.format("gsSPPopMatrixN(G_MTX_MODELVIEW, %s)",
                    w1 == -1 ? "?" : Long.toString(sftr(w1, 0, 32) / 64));
        case G_QUAD:
            // TODO: fix this
            return String.format("gsSP1Quadrangle(%d, %d, %d, %s, 0)", sftr(w0, 16, 8), sftr(w0, 8, 8), sftr(w0, 0, 8),
                    sftrStr(w1, 0, 8));
        case G_RDPFULLSYNC:
            return "gsDPFullSync()";
        // case G_RDPHALF_1:
        // case G_RDPHALF_2:
        case G_RDPLOADSYNC:
            return "gsDPLoadSync()";
        case G_RDPPIPESYNC:
            return "gsDPPipeSync()";
        case G_RDPSETOTHERMODE:
            return String.format("gsDPSetOtherMode(%s, %s)", sftrStr("0x%X", w0, 0, 24), sftrStr("0x%X", w1, 0, 32));
        case G_RDPTILESYNC:
            return "gsDPTileSync()";
        case G_SETBLENDCOLOR:
            return DisSetColor("gsDPBlendColor", w1, true);
        case G_SETCIMG:
            return DisSetImage("gsDPSetColorImage", w0, w1);
        case G_SETCOMBINE: {
            String a0 = ParseCombineColor(sftr(w0, 20, 4), 1);
            String b0 = ParseCombineColor(sftr(w1, 28, 4), 2);
            String c0 = ParseCombineColor(sftr(w0, 15, 5), 3);
            String d0 = ParseCombineColor(sftr(w1, 15, 3), 4);

            String Aa0 = ParseCombineAlpha(sftr(w0, 12, 3), 1);
            String Ab0 = ParseCombineAlpha(sftr(w1, 12, 3), 2);
            String Ac0 = ParseCombineAlpha(sftr(w0, 9, 3), 3);
            String Ad0 = ParseCombineAlpha(sftr(w1, 9, 3), 4);

            String a1 = ParseCombineColor(sftr(w0, 5, 4), 1);
            String b1 = ParseCombineColor(sftr(w1, 24, 4), 2);
            String c1 = ParseCombineColor(sftr(w0, 0, 5), 3);
            String d1 = ParseCombineColor(sftr(w1, 6, 3), 4);

            String Aa1 = ParseCombineAlpha(sftr(w1, 21, 3), 1);
            String Ab1 = ParseCombineAlpha(sftr(w1, 3, 3), 2);
            String Ac1 = ParseCombineAlpha(sftr(w1, 18, 3), 3);
            String Ad1 = ParseCombineAlpha(sftr(w1, 0, 3), 4);

            return String.format("gsDPSetCombineLERP(%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s,%s)", a0, b0, c0,
                    d0, Aa0, Ab0, Ac0, Ad0, a1, b1, c1, d1, Aa1, Ab1, Ac1, Ad1);
        }
        /* does not appear to be used in oot (not present in ucode_disas) */
        // case G_SETCONVERT:
        case G_SETENVCOLOR:
            return DisSetColor("gsDPSetEnvColor", w1, true);
        case G_SETFILLCOLOR:
            return DisSetColor("gsDPSetFillColor", w1, false);
        case G_SETFOGCOLOR:
            return DisSetColor("gsDPSetFogColor", w1, true);
        case G_SETKEYGB: {
            String wG = sftrStr(w0, 12, 12);
            String wB = sftrStr(w0, 0, 12);
            String cG = sftrStr(w1, 24, 8);
            String sG = sftrStr(w1, 16, 8);
            String cB = sftrStr(w1, 8, 8);
            String sB = sftrStr(w1, 0, 8);
            return String.format("gsDPSetKeyGB(%s, %s, %s, %s, %s, %s)", cG, sG, wG, cB, sB, wB);
        }
        case G_SETKEYR: {
            String wR = sftrStr(w1, 16, 8);
            String cR = sftrStr(w1, 8, 8);
            String sR = sftrStr(w1, 0, 8);
            return String.format("gsDPSetKeyR(%s, %s, %s)", cR, sR, wR);
        }
        case G_SETOTHERMODE_H:
        case G_SETOTHERMODE_L: {
            long len = sftr(w0, 0, 8) + 1;
            long sft = 32 - len - sftr(w0, 8, 8);
            return String.format("gsSPSetOtherMode(%s, %d, %X, %s)", id.toString(), sft, len,
                    sftrStr("0x%08X", w1, 0, 32));
        }
        case G_SETPRIMCOLOR: {
            long m = sftr(w0, 8, 8);
            long l = sftr(w0, 0, 8);
            String r = sftrStr(w1, 24, 8);
            String g = sftrStr(w1, 16, 8);
            String b = sftrStr(w1, 8, 8);
            String a = sftrStr(w1, 0, 8);
            return String.format("gsDPSetPrimColor(0x%02X, 0x%02X, %s, %s, %s, %s)", m, l, r, g, b, a);
        }
        case G_SETPRIMDEPTH: {
            String z = w1 == -1 ? "?" : Short.toString((short) sftr(w1, 16, 16));
            String dz = w1 == -1 ? "?" : Short.toString((short) sftr(w1, 0, 16));
            return String.format("gsDPSetPrimDepth(%s, %s)", z, dz);
        }
        case G_SETSCISSOR: {
            String mode = ParseScissorMode(sftr(w1, 24, 2));
            String ulx = fp(w0, 12, 10, 2, false);
            String uly = fp(w0, 0, 10, 2, false);
            String lrx = fp(w1, 12, 10, 2, false);
            String lry = fp(w1, 0, 10, 2, false);
            return String.format("gDPSetScissorFrac(%s, %s, %s, %s, %s)", mode, ulx, uly, lrx, lry);
        }
        case G_SETTILE: {
            String fmt = ParseImFmt(sftr(w0, 21, 3));
            String siz = ParseImSiz(sftr(w0, 19, 2));
            String tmem = sftrStr("0x%X", w0, 0, 9);
            String line = sftrStr(w0, 9, 9);
            String tile = ParseTile(sftr(w1, 24, 3));
            String palette = sftrStr(w1, 20, 4);
            String cmt = ParseMirrorClamp(sftr(w1, 18, 2));
            String cms = ParseMirrorClamp(sftr(w1, 8, 2));
            String shiftt = sftrStr(w1, 10, 4);
            String shifts = sftrStr(w1, 0, 4);
            String maskt = sftrStr(w1, 14, 4);
            String masks = sftrStr(w1, 4, 4);
            return String.format("gsDPSetTile(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", fmt, siz, line, tmem,
                    tile, palette, cmt, maskt, shiftt, cms, masks, shifts);
        }
        case G_SETTILESIZE:
            return DisLoadTileGeneric("gsDPSetTileSize", w0, w1);
        case G_SETTIMG:
            return DisSetImage("gsDPSetTextureImage", w0, w1);
        case G_SETZIMG:
            return String.format("gsDPSetDepthImage(%s)", sftrStr("0x%08X", w1, 0, 32));
        case G_SPNOOP:
            return "gsSPNoOp()";
        case G_TEXRECT: {
            String lrx = fp(w0, 12, 10, 2, false);
            String lry = fp(w0, 0, 10, 2, false);
            String tile = ParseTile(sftr(w1, 24, 3));
            String ulx = fp(w1, 12, 10, 2, false);
            String uly = fp(w1, 0, 10, 2, false);
            String uls = fp(half1, 16, 10, 5, true);
            String ult = fp(half1, 0, 10, 5, true);
            String dsdx = fp(half2, 16, 5, 10, true);
            String dtdy = fp(half2, 0, 5, 10, true);
            return String.format("gsSPTextureRectangle(%s, %s, %s, %s, %s, %s, %s, %s, %s)", ulx, uly, lrx, lry, tile,
                    uls, ult, dsdx, dtdy);
        }
        case G_TEXRECTFLIP: {
            String lrx = fp(w0, 12, 10, 2, false);
            String lry = fp(w0, 0, 10, 2, false);
            String tile = ParseTile(sftr(w1, 24, 3));
            String ulx = fp(w1, 12, 10, 2, false);
            String uly = fp(w1, 0, 10, 2, false);
            String uls = fp(half1, 16, 10, 5, true);
            String ult = fp(half1, 0, 10, 5, true);
            String dsdx = fp(half2, 16, 5, 10, true);
            String dtdy = fp(half2, 0, 5, 10, true);
            return String.format("gsSPTextureRectangleFlip(%s, %s, %s, %s, %s, %s, %s, %s, %s)", ulx, uly, lrx, lry,
                    tile, uls, ult, dsdx, dtdy);
        }
        case G_TEXTURE: {
            long level = sftr(w0, 11, 3);
            String on = sftr(w0, 1, 7) == 1 ? "G_ON" : "G_OFF";
            String tile = ParseTile(sftr(w0, 8, 3));
            String s = sftrStr("0x%X", w1, 16, 16);
            String t = sftrStr("0x%X", w1, 0, 16);
            return String.format("gsSPTexture(%s, %s, %d, %s, %s)", s, t, level, tile, on);
        }
        case G_TRI1:
            return String.format("gsSP1Triangle(%d, %d, %d, 0)", sftr(w0, 16, 8), sftr(w0, 8, 8), sftr(w0, 0, 8));
        case G_TRI2:
            return String.format("gsSP2Triangles(%d, %d, %d, 0, %s, %s, %s, 0)", sftr(w0, 16, 8), sftr(w0, 8, 8),
                    sftr(w0, 0, 8), sftrStr(w1, 16, 8), sftrStr(w1, 8, 8), sftrStr(w1, 0, 8));
        case G_VTX: {
            long numv = sftr(w0, 12, 8);
            long vbidx = sftr(w0, 1, 7) - numv;
            String vaddr = sftrStr("0x%08X", w1, 0, 32);
            return String.format("gsSPVertex(%s, %d, %d)", vaddr, numv, vbidx);
        }

        case Invalid:
            return "Invalid";
        default:
            return id.toString();
        }
    }
}

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

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this file system
 * does.
 */
@FileSystemInfo(type = "zelda64dmadatafs", // ([a-z0-9]+ only)
        description = "Zelda 64 DMA Filesystem", factory = Zelda64FileSystem.MyFileSystemFactory.class)
public class Zelda64FileSystem implements GFileSystem {

    private final FSRLRoot fsFSRL;
    private FileSystemIndexHelper<Zelda64File> fsih;
    private FileSystemRefManager refManager = new FileSystemRefManager(this);

    private Zelda64Game mGame;
    private boolean mClosed;

    public Zelda64FileSystem(FSRLRoot fsFSRL, Zelda64Game game) {
        this.fsFSRL = fsFSRL;
        this.mGame = game;
        this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
        this.mClosed = false;
    }

    public void mount(TaskMonitor monitor) {
        monitor.setMessage("Opening " + Zelda64FileSystem.class.getSimpleName() + "...");

        for (Zelda64File file : mGame.mFiles) {
            if (monitor.isCancelled()) {
                break;
            }
            fsih.storeFile(String.format("%08X", file.mVromStart), fsih.getFileCount(), false,
                    file.Valid() ? file.mData.length : 0, file);
        }
    }

    @Override
    public void close() throws IOException {
        refManager.onClose();
        fsih.clear();
        mClosed = true;
    }

    @Override
    public String getName() {
        return fsFSRL.getContainer().getName();
    }

    @Override
    public FSRLRoot getFSRL() {
        return fsFSRL;
    }

    @Override
    public boolean isClosed() {
        return mClosed;
    }

    @Override
    public int getFileCount() {
        return fsih.getFileCount();
    }

    @Override
    public FileSystemRefManager getRefManager() {
        return refManager;
    }

    @Override
    public GFile lookup(String path) throws IOException {
        return fsih.lookup(path);
    }

    @Override
    public InputStream getInputStream(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
        Zelda64File entry = fsih.getMetadata(file);
        return (entry != null && !entry.mDeleted && entry.Valid())
                ? new ByteProviderInputStream(new ByteArrayProvider(entry.mData), 0, entry.mData.length)
                : null;
    }

    @Override
    public List<GFile> getListing(GFile directory) throws IOException {
        return fsih.getListing(directory);
    }

    @Override
    public String getInfo(GFile file, TaskMonitor monitor) {
        Zelda64File metadata = fsih.getMetadata(file);
        return (metadata == null) ? null : FSUtilities.infoMapToString(getInfoMap(metadata));
    }

    public Map<String, String> getInfoMap(Zelda64File file) {
        Map<String, String> info = new LinkedHashMap<>();

        if (!file.Valid()) {
            info.put("Info", String.format("%08X-%08X (INVALID)", -1, -1));
        } else {
            info.put("VROM", String.format("%08X-%08X", file.mVromStart, file.mVromStart + file.mData.length)
                    + (file.mDeleted ? " (DELETED)" : ""));
            info.put("ROM", String.format("%08X-%08X", file.mRomStart, file.mRomEnd + file.mData.length));
            info.put("Size", String.format("%08X", file.mData.length));
            if (file.mCompressed)
                info.put("Compressed Size", String.format("%08X", file.mRomEnd - file.mRomStart));
        }
        return info;
    }

    public static class MyFileSystemFactory implements GFileSystemFactoryFull<Zelda64FileSystem>, GFileSystemProbeFull {

        @Override
        public Zelda64FileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider byteProvider,
                File containerFile, FileSystemService fsService, TaskMonitor monitor)
                throws IOException, CancelledException {
            try {
                byte[] data = byteProvider.getInputStream(0).readAllBytes();
                Zelda64Game game = new Zelda64Game(data, true, monitor);
                byteProvider.close();
                Zelda64FileSystem fs = new Zelda64FileSystem(targetFSRL, game);
                fs.mount(monitor);
                return fs;
            } catch (Exception e) {
                e.printStackTrace();
                Msg.error(this, e.getMessage());
                throw new CancelledException();
            }
        }

        @Override
        public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
                FileSystemService fsService, TaskMonitor monitor) throws IOException, CancelledException {

            byte[] data = byteProvider.getInputStream(0).readAllBytes();
            try {
                new Zelda64Game(data, false, null);
                return true;
            } catch (Exception e) {
                return false;
            }

        }
    }
}

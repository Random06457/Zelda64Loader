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
@FileSystemInfo(type = "mm64dmadatafs", // ([a-z0-9]+ only)
        description = "Majora's Mask 64 DMA Filesystem", factory = Mm64FileSystem.MyFileSystemFactory.class)
public class Mm64FileSystem implements GFileSystem {

    private final FSRLRoot fsFSRL;
    private FileSystemIndexHelper<Mm64File> fsih;
    private FileSystemRefManager refManager = new FileSystemRefManager(this);

    private Mm64Game game;
    private boolean closed;

    public Mm64FileSystem(FSRLRoot fsFSRL, Mm64Game game) {
        this.fsFSRL = fsFSRL;
        this.game = game;
        this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
        this.closed = false;
    }

    public void mount(TaskMonitor monitor) {
        monitor.setMessage("Opening " + Mm64FileSystem.class.getSimpleName() + "...");

        for (Mm64File file : game.mFiles) {
            if (monitor.isCancelled()) {
                break;
            }
            fsih.storeFile(String.format("%08X", file.VRomStart), fsih.getFileCount(), false,
                    file.Valid() ? file.Data.length : 0, file);
        }
    }

    @Override
    public void close() throws IOException {
        refManager.onClose();
        fsih.clear();
        closed = true;
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
        return closed;
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
        Mm64File entry = fsih.getMetadata(file);
        return (entry != null && !entry.Deleted && entry.Valid())
                ? new ByteProviderInputStream(new ByteArrayProvider(entry.Data), 0, entry.Data.length)
                : null;
    }

    @Override
    public List<GFile> getListing(GFile directory) throws IOException {
        return fsih.getListing(directory);
    }

    @Override
    public String getInfo(GFile file, TaskMonitor monitor) {
        Mm64File metadata = fsih.getMetadata(file);
        return (metadata == null) ? null : FSUtilities.infoMapToString(getInfoMap(metadata));
    }

    public Map<String, String> getInfoMap(Mm64File file) {
        Map<String, String> info = new LinkedHashMap<>();

        if (!file.Valid()) {
            info.put("Info", String.format("%08X-%08X (INVALID)", -1, -1));
        } else {
            info.put("VROM", String.format("%08X-%08X", file.VRomStart, file.VRomStart + file.Data.length)
                    + (file.Deleted ? " (DELETED)" : ""));
            info.put("ROM", String.format("%08X-%08X", file.RomStart, file.RomEnd + file.Data.length));
            info.put("Size", String.format("%08X", file.Data.length));
            if (file.Compressed)
                info.put("Compressed Size", String.format("%08X", file.RomEnd - file.RomStart));
        }
        return info;
    }

    public static class MyFileSystemFactory implements GFileSystemFactoryFull<Mm64FileSystem>, GFileSystemProbeFull {

        @Override
        public Mm64FileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider byteProvider,
                File containerFile, FileSystemService fsService, TaskMonitor monitor)
                throws IOException, CancelledException {
            try {
                byte[] data = byteProvider.getInputStream(0).readAllBytes();
                Mm64Game game = new Mm64Game(data, true, monitor);
                byteProvider.close();
                Mm64FileSystem fs = new Mm64FileSystem(targetFSRL, game);
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
                new Mm64Game(data, false, null);
                return true;
            } catch (Exception e) {
                return false;
            }

        }
    }
}

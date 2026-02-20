import cwlib.enums.ResourceType;
import cwlib.resources.RSlotList;
import cwlib.structs.slot.Slot;
import cwlib.types.SerializedResource;
import cwlib.types.archives.Fat;
import cwlib.types.archives.SaveArchive;
import cwlib.types.data.SHA1;
import cwlib.types.data.WrappedResource;
import cwlib.util.Bytes;
import cwlib.util.Crypto;
import cwlib.util.FileIO;
import cwlib.util.GsonUtils;
import cwlib.util.Resources;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;

public class BatchLevelToJson {

    /**
     * Reassembles and decrypts a split/encrypted PS3 save archive.
     * Files on disk are XXTEA-encrypted chunks named "0", "1", "2", etc.
     * The last chunk has "FAR4" (4 bytes) appended after the encrypted data.
     */
    private static byte[] reassembleArchive(File levelFolder) {
        ByteArrayOutputStream assembled = new ByteArrayOutputStream();

        int chunkIndex = 0;
        while (true) {
            File chunkFile = new File(levelFolder, String.valueOf(chunkIndex));
            if (!chunkFile.exists()) break;

            byte[] chunkData = FileIO.read(chunkFile.getAbsolutePath());
            if (chunkData == null) break;

            // Check if this is the last chunk (ends with "FAR4" magic)
            boolean isLastChunk = false;
            if (chunkData.length >= 4) {
                byte[] lastFour = Arrays.copyOfRange(chunkData, chunkData.length - 4, chunkData.length);
                // FAR4 = 0x46 0x41 0x52 0x34
                if (lastFour[0] == 0x46 && lastFour[1] == 0x41 &&
                    lastFour[2] == 0x52 && lastFour[3] == 0x34) {
                    isLastChunk = true;
                }
            }

            byte[] encrypted;
            byte[] trailer = null;

            if (isLastChunk) {
                // Strip the FAR4 trailer before decrypting
                encrypted = Arrays.copyOfRange(chunkData, 0, chunkData.length - 4);
                trailer = Arrays.copyOfRange(chunkData, chunkData.length - 4, chunkData.length);
            } else {
                encrypted = chunkData;
            }

            // Decrypt the chunk
            byte[] decrypted = Crypto.XXTEA(encrypted, true);
            assembled.write(decrypted, 0, decrypted.length);

            // Re-append FAR4 trailer to the end of the last chunk
            if (trailer != null) {
                assembled.write(trailer, 0, trailer.length);
            }

            chunkIndex++;
        }

        if (chunkIndex == 0) return null;

        System.out.println("  Reassembled " + chunkIndex + " chunk(s);");
        return assembled.toByteArray();
    }

    public static void main(String[] args) {
        File inputDir = new File("input");
        File outputDir = new File("output");

        if (!inputDir.exists()) {
            System.err.println("Input directory does not exist: " + inputDir.getAbsolutePath());
            return;
        }
        if (!outputDir.exists()) outputDir.mkdirs();

        File[] levelFolders = inputDir.listFiles(f ->
            f.isDirectory() && f.getName().contains("LEVEL")
        );

        if (levelFolders == null || levelFolders.length == 0) {
            System.err.println("No LEVEL folders found in " + inputDir.getAbsolutePath());
            return;
        }

        System.out.println("Found " + levelFolders.length + " level folder(s).
");

        int success = 0, failed = 0;

        for (File levelFolder : levelFolders) {
            String folderName = levelFolder.getName();

            // Check that at least the "0" chunk exists
            if (!new File(levelFolder, "0").exists()) {
                System.err.println("[SKIP] No '0' file in " + folderName);
                failed++;
                continue;
            }

            System.out.println("[PROCESSING] " + folderName);

            try {
                // Reassemble and decrypt the split archive
                byte[] archiveData = reassembleArchive(levelFolder);
                if (archiveData == null) {
                    System.err.println("[FAIL] Could not reassemble archive for " + folderName);
                    failed++;
                    continue;
                }

                // Parse the reassembled save archive
                SaveArchive archive = new SaveArchive(archiveData);

                byte[] levelData = null;
                SHA1 levelHash = null;

                SHA1 rootHash = archive.getKey().getRootHash();
                ResourceType rootType = archive.getKey().getRootType();

                if (rootType == ResourceType.SLOT_LIST) {
                    byte[] slotListData = archive.extract(rootHash);
                    if (slotListData != null) {
                        RSlotList slotList = new SerializedResource(slotListData)
                            .loadResource(RSlotList.class);
                        ArrayList<Slot> slots = slotList.getSlots();
                        if (!slots.isEmpty()) {
                            Slot slot = slots.get(0);
                            if (slot.root != null && !slot.root.isGUID()) {
                                levelHash = slot.root.getSHA1();
                                levelData = archive.extract(levelHash);
                            }
                        }
                    }
                } else if (rootType == ResourceType.LEVEL) {
                    levelData = archive.extract(rootHash);
                    levelHash = rootHash;
                }

                // Fallback: scan all entries for a LEVEL resource
                if (levelData == null) {
                    for (Fat fat : archive) {
                        byte[] data = fat.extract();
                        ResourceType type = Resources.getResourceType(data);
                        if (type == ResourceType.LEVEL) {
                            levelData = data;
                            levelHash = fat.getSHA1();
                            break;
                        }
                    }
                }

                if (levelData == null) {
                    System.err.println("[FAIL] No level resource found in " + folderName);
                    failed++;
                    continue;
                }

                SerializedResource resource = new SerializedResource(levelData);
                WrappedResource wrapper = new WrappedResource(resource);
                String json = GsonUtils.toJSON(wrapper, resource.getRevision());

                File jsonFile = new File(outputDir, folderName + ".json");
                FileIO.write(json.getBytes(), jsonFile.getAbsolutePath());

                System.out.println("[OK] " + folderName + " -> " + jsonFile.getName());
                success++;

            } catch (Exception ex) {
                System.err.println("[FAIL] " + folderName + ": " + ex.getMessage());
                ex.printStackTrace();
                failed++;
            }
        }

        System.out.println("\n========================================");
        System.out.println("Done! Success: " + success + ", Failed: " + failed);
        System.out.println("Output: " + outputDir.getAbsolutePath());
    }

}
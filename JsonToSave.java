import cwlib.enums.ResourceType;
import cwlib.types.archives.SaveArchive;
import cwlib.types.data.Revision;
import cwlib.types.data.SHA1;
import cwlib.types.data.WrappedResource;
import cwlib.util.Crypto;
import cwlib.util.FileIO;
import cwlib.util.GsonUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;

public class JsonToSave {

    private static final int CHUNK_SIZE = 0xE000;

    private static void splitAndEncrypt(byte[] archiveData, File outputFolder) {
        byte[] body;
        byte[] trailer;

        int len = archiveData.length;
        if (len >= 4) {
            byte[] lastFour = Arrays.copyOfRange(archiveData, len - 4, len);
            if (lastFour[0] == 0x46 && lastFour[1] == 0x41 &&
                lastFour[2] == 0x52 && lastFour[3] == 0x34) {
                body = Arrays.copyOfRange(archiveData, 0, len - 4);
                trailer = lastFour;
            } else {
                body = archiveData;
                trailer = new byte[] { 0x46, 0x41, 0x52, 0x34 };
            }
        } else {
            body = archiveData;
            trailer = new byte[] { 0x46, 0x41, 0x52, 0x34 };
        }

        int chunkIndex = 0;
        int offset = 0;

        while (offset < body.length) {
            int remaining = body.length - offset;
            int thisChunkSize = Math.min(remaining, CHUNK_SIZE);
            byte[] chunk = Arrays.copyOfRange(body, offset, offset + thisChunkSize);
            boolean isLast = (offset + thisChunkSize >= body.length);

            byte[] encrypted = Crypto.XXTEA(chunk, false);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(encrypted, 0, encrypted.length);

            if (isLast) {
                out.write(trailer, 0, trailer.length);
            }

            File chunkFile = new File(outputFolder, String.valueOf(chunkIndex));
            FileIO.write(out.toByteArray(), chunkFile.getAbsolutePath());

            offset += thisChunkSize;
            chunkIndex++;
        }

        System.out.println("  Split into " + chunkIndex + " encrypted chunk(s)");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java JsonToSave <input.json> <output_folder>");
            System.out.println("Example: java JsonToSave LEVEL0001.json rebuilt/LEVEL0001");
            return;
        }

        File jsonFile = new File(args[0]);
        File outputFolder = new File(args[1]);

        // FAR4 for PS3 saves
        // Adjust gameRevision to match your save:
        //   LBP1: new Revision(0x272)
        //   LBP2: new Revision(0x3F8)
        //   LBP3: new Revision(0x3E2, 0x4C44, 0x0017)
        int farRevision = 4;
        Revision gameRevision = new Revision(0x3F8);

        if (!jsonFile.exists()) {
            System.err.println("Input file does not exist: " + jsonFile.getAbsolutePath());
            return;
        }
        if (!outputFolder.exists()) outputFolder.mkdirs();

        System.out.println("[PROCESSING] " + jsonFile.getName());

        try {
            String json = FileIO.readString(Path.of(jsonFile.getAbsolutePath()));
            WrappedResource wrapper = GsonUtils.fromJSON(json, WrappedResource.class);

            byte[] levelData = wrapper.build();
            SHA1 levelHash = Crypto.SHA1(levelData);

            System.out.println("  Level resource: " + levelData.length + " bytes, SHA1: " + levelHash);

            SaveArchive archive = new SaveArchive(gameRevision, farRevision);
            archive.add(levelData);
            archive.getKey().setRootType(ResourceType.LEVEL);
            archive.getKey().setRootHash(levelHash);

            byte[] archiveData = archive.build(true);

            splitAndEncrypt(archiveData, outputFolder);

            System.out.println("[OK] " + jsonFile.getName() + " -> " + outputFolder.getPath());

        } catch (Exception ex) {
            System.err.println("[FAIL] " + ex.getMessage());
            ex.printStackTrace();
        }
    }
}
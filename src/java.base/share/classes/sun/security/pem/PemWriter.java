package sun.security.pem;

import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.Flushable;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PEMEncoder;
import java.util.Base64;
import java.util.List;

import sun.security.pem.Pem.UnknownEntry;

/**
 * Writing PEM entries to a stream.
 */
class PemWriter implements Closeable, Flushable {

    private BufferedWriter writer;
    private boolean writeAliasLine;

    PemWriter(OutputStream os, boolean writeAliasLine) {
        writer = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
        this.writeAliasLine = writeAliasLine;
    }

    void writeEntry(Pem.Entry entry) {
        PEMEncoder encoder = PEMEncoder.of();
        try {
            switch (entry) {
                case Pem.EncryptedPrivateKeyEntry encryptedPrivateKeyEntry: writeEncodedPemEntry(entry.alias, encoder.encodeToString(encryptedPrivateKeyEntry.encryptedPrivateKey)); break;
                case Pem.PrivateKeyEntry privateKeyEntry: writeEncodedPemEntry(entry.alias, encoder.encodeToString(privateKeyEntry.privateKey)); break;
                case Pem.CertificateEntry certificateEntry: writeEncodedPemEntry(entry.alias, encoder.encodeToString(certificateEntry.certificate)); break;
                case Pem.UnknownEntry unknownEntry: writePemEntry(entry.alias, unknownEntry.encoding, unknownEntry.pemBeginLine, unknownEntry.pemEndLine); break;
                default: writePemEntry(entry.alias, entry.encoding, Pem.BEGIN_CERTIFICATE, Pem.END_CERTIFICATE); break;
            }
        } catch (IOException e) {
            throw new PemKeystoreException("failed encoding and writing PEM entry", e);
        }
    }

    private void writeEncodedPemEntry(String alias, String encodedEntry) throws IOException {
        if (writeAliasLine && alias != null) {
            writer.write("Alias: ");
            writer.write(alias);
            writer.write("\n");
        }
        writer.write(encodedEntry);
        writer.write("\n");
        writer.flush();
    }

    private void writePemEntry(String alias, byte[] encoding, String beginLine, String endLine) throws IOException {
        StringBuilder buffer = new StringBuilder(); 
        buffer.append(beginLine);
        buffer.append("\n");
        buffer.append(Base64.getMimeEncoder(64, new byte[] { 0x0a}).encodeToString(encoding));
        buffer.append("\n");
        buffer.append(endLine);

        writeEncodedPemEntry(alias, buffer.toString());
    }

    @Override
    public void close() throws IOException {
        this.writer.close();
    }

    @Override
    public void flush() throws IOException {
        this.writer.flush();
    }

    static void write(Path filePath, Pem.Entry entry) {
        try (PemWriter pw = new PemWriter(new FileOutputStream(filePath.toFile()), false)) {
            pw.writeEntry(entry);
        } catch (IOException e) {
            throw new PemKeystoreException("failed writing PEM entry to file " + filePath, e);
        }
    }

    static void write(Path filePath, List<Pem.CertificateEntry> certificateChainEntries) {
        try (PemWriter pw = new PemWriter(new FileOutputStream(filePath.toFile()), false)) {
            certificateChainEntries.stream().forEach(c -> pw.writeEntry(c));
        } catch (IOException e) {
            throw new PemKeystoreException("failed writing PEM entry to file " + filePath, e);
        }
    }

}

package sun.security.pem;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.PEMDecoder;
import java.security.PrivateKey;
import java.security.SecurityObject;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import javax.crypto.EncryptedPrivateKeyInfo;

/**
 * Reading PEM entries from a stream.
 */
class PemReader implements Closeable {

    private BufferedReader reader;
    private String aliasCandidate;

    PemReader(InputStream is, String aliasCandidate) {
        reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        this.aliasCandidate = aliasCandidate;
    }

    List<Pem.Entry> readEntries() throws IOException {
        List<Pem.Entry> entries = new ArrayList<>();

        Pem.Entry entry;
        while ((entry = readEntry()) != null) {
            entries.add(entry);
        }

        return entries;
    }

    Pem.Entry readEntry() throws IOException {
        String alias = this.aliasCandidate;
        
        // read up to and including "-----BEGIN..." line, catching alias info
        String line = null;
        String pemBeginLine = null;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith(Pem.BEGIN)) {
                pemBeginLine = line;
                break;
            }
            String trimmedLine = line.trim();
            if (trimmedLine.isEmpty()) {
                // ignore empty lines
                continue;
            }
            if (trimmedLine.toLowerCase(Locale.US).startsWith("alias:")) {
                alias = trimmedLine.substring(trimmedLine.indexOf(':') + 1, trimmedLine.length()).trim();
            }
        }
        
        // read up to and including "-----END..." line
        StringBuilder base64Builder = new StringBuilder(1024);
        String pemEndLine = null;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith(Pem.END)) {
                pemEndLine = line;
                break;
            }
            base64Builder.append(line);
        }
        String base64Data = base64Builder.toString().trim();
        if (base64Data.length() == 0) {
            return null;
        }

        StringBuilder pemBlockBuffer = new StringBuilder(1024);
        pemBlockBuffer.append(pemBeginLine).append('\n');
        pemBlockBuffer.append(base64Data);
        pemBlockBuffer.append(pemEndLine).append('\n');

        System.out.println("pemBlockBuffer:");
        System.out.println(pemBlockBuffer.toString());

        SecurityObject decodedObject = new PEMDecoder().decode(pemBlockBuffer.toString());

        Pem.Entry entry = switch (decodedObject) {
            case PrivateKey privateKey -> new Pem.PrivateKeyEntry(alias, privateKey);
            case X509Certificate certificate -> new Pem.CertificateEntry(alias, certificate);
            case EncryptedPrivateKeyInfo encryptedPrivateKey -> new Pem.EncryptedPrivateKeyEntry(alias, encryptedPrivateKey);
            default -> {
                Pem.UnknownEntry unknownEntry = new Pem.UnknownEntry(alias, pemBeginLine);
                unknownEntry.initFromEncoding(Base64.getMimeDecoder().decode(base64Builder.toString()));
                yield unknownEntry;
            }
        };

        return entry;
    }

    @Override
    public void close() throws IOException {
        this.reader.close();
    }

}

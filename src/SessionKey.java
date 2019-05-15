import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

public class SessionKey {

    private static final String algorithm = "AES";
    private final SecretKey key;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keylength);
        this.key = keyGenerator.generateKey();
    }

    public SessionKey(byte[] encodedkey) {
        this.key = new SecretKeySpec(encodedkey, 0, encodedkey.length, algorithm);
    }

    SecretKey getSecretKey() {
        return this.key;
    }

    String encodeKey() {
        return Base64.getEncoder().encodeToString(this.key.getEncoded());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SessionKey that = (SessionKey) o;
        return Objects.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key);
    }

}

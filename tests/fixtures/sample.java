// Synthetic Java snippet for detector tests
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class Sample {
    public void rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }
    public void ec() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        Signature sig = Signature.getInstance("SHA256withECDSA");
    }
}

// Fixture for PQC-ready detection: Bouncy Castle PQC (Kyber/Dilithium)
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import java.security.KeyPairGenerator;
import java.security.Security;

public class PqcSample {
    public static void main(String[] args) throws Exception {
        // Kyber KEM via getInstance (e.g. JDK 21+ or BC provider)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber768");
    }
}

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import java.io.File;
import java.io.FileInputStream;

import java.io.FileNotFoundException;

import java.io.IOException;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import java.security.cert.CertificateException;

import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

public class JwtConvert {

    public JwtConvert() {
    }

    static String keyStoreFileName = "classes/keystore.private";
    static String keyStorePassword = "";
    static String alias = "assert";
               
    public static void main(String[] args) throws ExecutionException, InterruptedException, KeyStoreException,
                                                  NoSuchAlgorithmException, UnrecoverableKeyException,
                                                  FileNotFoundException, IOException, CertificateException {
        // Read the private key from the key store
        FileInputStream is = new FileInputStream(keyStoreFileName);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(is, keyStorePassword.toCharArray());
        Key key = ks.getKey(alias, keyStorePassword.toCharArray());
        
        JwtBuilder jwtBuilder = Jwts.builder();
        
        // Set up the header first
        jwtBuilder.setHeaderParam("alg", "RS256");
        jwtBuilder.setHeaderParam("typ", "JWT");
        jwtBuilder.setHeaderParam("kid", "assert"); // This property must be specified. If missing, you will get "Invalid User Assertion"
        
        jwtBuilder.claim("sub", "cristiano.hoshikawa@oracle.com"); // subject = username
        jwtBuilder.claim("prn", "cristiano.hoshikawa@oracle.com"); // principle = username
        
        // The following combination works
//            jwtBuilder.claim("aud", "https://identity.oraclecloud.com/"); // audience = a fixed value to this value for IDCS
//            jwtBuilder.claim("iss", "https://identity.oraclecloud.com/"); // Issuer = fixed 
        
        // The following combination works
        jwtBuilder.claim("aud", "https://identity.oraclecloud.com/"); // audience = a fixed value to this value for IDCS
        jwtBuilder.claim("iss", "c54859b3b7054cxxxxea864cb211a21c"); // Issuer = fixed to IDCS app client id 

        UUID uuid = UUID.randomUUID();
        
        Date date = new Date();
        long iatSeconds = date.getTime() / 1000;
        long expSeconds = iatSeconds + 1 * 60 * 60; // set the JWT expiration to 1 hour. Can be longer
        
        jwtBuilder.claim("iat", iatSeconds);
        jwtBuilder.claim("exp", expSeconds);
        jwtBuilder.claim("jti", uuid.toString());

        // Sign the token with the private key
        String jwt = jwtBuilder.signWith(key).compact();
        System.out.println(jwt);
    }
}

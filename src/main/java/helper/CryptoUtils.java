package helper;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {
    public static Boolean verifySHA256withRSAandPSS(RSAPublicKey verificationKey, byte[] message, byte[] signature, int saltLength){
        RSAKeyParameters keyParameters = new RSAKeyParameters(false, verificationKey.getModulus(), verificationKey.getPublicExponent());

        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), saltLength);
        signer.init(false, keyParameters);
        signer.update(message, 0, message.length);

        return signer.verifySignature(signature);
    }

    public static RSAKey createRSAKeyFromString(String key) {
        StringBuilder lines = new StringBuilder();
        BufferedReader reader = new BufferedReader(new StringReader(key));
        String line;
        while (true){
            try {
                if ((line = reader.readLine()) == null) break;
                lines.append(line);
            } catch (IOException e) {
                System.err.println("Failed reading key string.");
                e.printStackTrace();
            }
        }

        String pem = lines.toString();
        String format = pem.substring(11, 14);

        switch (format){
            case "RSA": return createRSAPublicKeyFromPKCS1String(pem);
            case "PUB": return createRSAPublicKeyFromX509String(pem);
            case "PRI": return createRSAPrivateKeyFromPKCS8String(pem);
            default: return null;
        }
    }

    private static RSAPublicKey createRSAPublicKeyFromPKCS1String(String pem) {
        pem = pem.replace("-----BEGIN RSA PUBLIC KEY-----", "");
        pem = pem.replace("-----END RSA PUBLIC KEY-----", "");
        pem = pem.replaceAll("\\s+","");

        byte[] keyBytes = Base64.getDecoder().decode(pem);

        AlgorithmIdentifier rsaAlgId = AlgorithmIdentifier.getInstance(PKCSObjectIdentifiers.rsaEncryption);
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(rsaAlgId, keyBytes);
        try {
            KeySpec keySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            System.err.println("Failed creating RSAPublicKey from string.");
            e.printStackTrace();
        }
        return null;
    }

    private static RSAPublicKey createRSAPublicKeyFromX509String(String pem) {
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "");
        pem = pem.replace("-----END PUBLIC KEY-----", "");
        pem = pem.replaceAll("\\s+","");

        byte[] keyBytes = Base64.getDecoder().decode(pem);
        KeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Failed creating RSAPublicKey from string.");
            e.printStackTrace();
        }
        return null;
    }

    private static RSAPrivateKey createRSAPrivateKeyFromPKCS8String(String pem){
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pem = pem.replace("-----END PRIVATE KEY-----", "");
        pem = pem.replaceAll("\\s+","");

        byte[] keyBytes = Base64.getDecoder().decode(pem);
        KeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Failed creating RSAPrivateKey from string.");
            e.printStackTrace();
        }
        return null;
    }
}

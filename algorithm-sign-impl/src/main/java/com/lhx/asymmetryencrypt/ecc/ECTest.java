package com.lhx.asymmetryencrypt.ecc;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class ECTest {

    public final static String PUBLIC_KEY_FILE = "D:\\ljj\\ecc\\public.key";

    public final static String PRIVATE_KEY_FILE = "D:\\ljj\\ecc\\private.key";

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    private static void genKeyPair() throws Exception {

        /** 算法要求有一个可信任的随机数源 */
        SecureRandom secureRandom = new SecureRandom();

        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC","BC");

        /** 利用随机数据源初始化这个KeyPairGenerator对象 */
        keyPairGenerator.initialize(256, secureRandom);

        /** 生成密匙对 */
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        /** 得到公钥 */
        Key publicKey = keyPair.getPublic();

        /** 得到私钥 */
        Key privateKey = keyPair.getPrivate();

        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();

        String publicKeyBase64 = new BASE64Encoder().encode(publicKeyBytes);
        String privateKeyBase64 = new BASE64Encoder().encode(privateKeyBytes);

        System.out.println("publicKeyBase64:" + publicKeyBase64);
        System.out.println("privateKeyBase64:" + privateKeyBase64);
        FileUtils.writeStringToFile(new File(PUBLIC_KEY_FILE),publicKeyBase64,"UTF-8");
        FileUtils.writeStringToFile(new File(PRIVATE_KEY_FILE),privateKeyBase64,"UTF-8");
    }

    public static String  encrypt( ECPublicKey publicKey,String text) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher encrypter = Cipher.getInstance("ECIES", "BC");
        encrypter.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] e = encrypter.doFinal(text.getBytes("UTF-8"));
        String encoded = Base64.getEncoder().encodeToString(e);
        return encoded;
    }


    public static String decrypt(ECPrivateKey privateKey,String encryptbase64) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] decoded = Base64.getDecoder().decode(encryptbase64);
        Cipher decrypter = Cipher.getInstance("ECIES", "BC");
        decrypter.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decrypter.doFinal(decoded),"UTF-8");
    }


    public static ECPublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        return getPublicKey(FileUtils.readFileToString(new File(PUBLIC_KEY_FILE),"UTF-8"));
    }
    //将Base64编码后的公钥转换成PublicKey对象
    public static ECPublicKey getPublicKey(String publicKeyBase64) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        ECPublicKey publicKey = null;
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(new BASE64Decoder().decodeBuffer(publicKeyBase64));
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        publicKey =(ECPublicKey) keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public static ECPrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        return getPrivateKey(FileUtils.readFileToString(new File(PRIVATE_KEY_FILE),"UTF-8"));
    }

    //将Base64编码后的私钥转换成PrivateKey对象
    public static ECPrivateKey getPrivateKey(String privateKeyBase64) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        ECPrivateKey privateKey = null;
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        PKCS8EncodedKeySpec keySpecPKCS8  = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(privateKeyBase64));
        privateKey =  (ECPrivateKey)keyFactory.generatePrivate(keySpecPKCS8);
        return privateKey;
    }

    public static void main(String[] argu) throws Exception {
        //test1();
        ECPublicKey publicKey = getPublicKey();
        ECPrivateKey privateKey = getPrivateKey();
        String responseText = "  response...  ";
        String sign = getSignature(privateKey,responseText);
        System.out.println("sign "+sign);
        System.out.println(" verify : "+ verifySignature(publicKey,responseText,sign));

    }

    public static void test1() throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        String text = "";
        for (int i = 0; i < 1024; i++) {
            text += "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ";
        }
        ECPublicKey publicKey = getPublicKey();
        ECPrivateKey privateKey = getPrivateKey();
        String enc = encrypt(publicKey,text);
        long begin = System.currentTimeMillis();
        for (int j=0;j<1000;j++)
        {
            decrypt(privateKey,enc);
            /*System.out.println(" before encrypt : " +text);
            System.out.println(" after encrypt : " +enc);
            System.out.println(" after decrypt : "+ decrypt(privateKey,enc));*/
        }
        long end = System.currentTimeMillis();
        System.out.println(" avg time "+(end-begin)/1000+" ms ");
    }

    /**
     * 私钥签名
     * @param ecPrivateKey
     * @param text
     * @return
     */
    public static String getSignature(ECPrivateKey ecPrivateKey,String text) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Signature signature = Signature.getInstance("SHA1withECDSA");
        signature.initSign(ecPrivateKey);
        signature.update(text.getBytes());
        byte[] res = signature.sign();
        System.out.println("签名：" + Hex.encodeHexString(res));
        return Hex.encodeHexString(res);
    }

    /**
     * 公钥验证
     * @param ecPublicKey
     * @param text
     * @param sign
     * @return
     * @throws DecoderException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static boolean verifySignature(ECPublicKey ecPublicKey,String text,String sign) throws DecoderException, SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA1withECDSA");
        signature.initVerify(ecPublicKey);
        signature.update(text.getBytes());
        return  signature.verify(Hex.decodeHex(sign));
    }

    public static void test() throws Exception {
        genKeyPair();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC",
                "BC");
        keyPairGenerator.initialize(256, new SecureRandom());
        KeyPair kp = keyPairGenerator.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();
        String publicKeyBase64 = new BASE64Encoder().encode(publicKeyBytes);
        String privateKeyBase64 = new BASE64Encoder().encode(privateKeyBytes);
        System.out.println("xxxxxxxxxxxxx" +publicKeyBase64);
        System.out.println("yyyyyyyyyyyyy" +privateKeyBase64);
        publicKey = null;
        privateKey = null;
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(new BASE64Decoder().decodeBuffer(publicKeyBase64));
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        publicKey =(ECPublicKey) keyFactory.generatePublic(keySpec);
        PKCS8EncodedKeySpec keySpecPKCS8  = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(privateKeyBase64));
        privateKey =  (ECPrivateKey)keyFactory.generatePrivate(keySpecPKCS8);

        byte[] publicKeyBytes2 = publicKey.getEncoded();
        byte[] privateKeyBytes2 = privateKey.getEncoded();
        String publicKeyBase642 = new BASE64Encoder().encode(publicKeyBytes2);
        String privateKeyBase642 = new BASE64Encoder().encode(privateKeyBytes2);

        System.out.println("xxxxxxxxxxxxx" +publicKeyBase642);
        System.out.println("yyyyyyyyyyyyy" +privateKeyBase642);

        Cipher encrypter = Cipher.getInstance("ECIES", "BC");
        Cipher decrypter = Cipher.getInstance("ECIES", "BC");
        encrypter.init(Cipher.ENCRYPT_MODE, publicKey);
        decrypter.init(Cipher.DECRYPT_MODE, privateKey);

        String text = "";
        for (int i = 0; i < 1024; i++) {
            text += "This is a test!@#$This is a test!@#$This is a test!@#This is a test!@#$This is a test!@#$This is a test!@#This is a test!@#$This is a test!@#$This is a test!@#";
        }
        byte[] e = encrypter.doFinal(text.getBytes("UTF-8"));
        System.out.println("Encrypted, length = " + e.length);

        byte[] de = decrypter.doFinal(e);
        String result = new String(de, "UTF-8");

        // System.out.println("Decrypted :" + result);
        if (result.equals(text)) {
            System.out.println("OK!");
        }
    }
}

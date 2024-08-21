package aes_server;
import java.net.*; 
import java.io.*;
import java.nio.charset.StandardCharsets; 
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;



public class AES_Server 
{
    private static final String SECRET_KEY = "our_super_secret_key_for_AES";
    private static final String SALT = "iqrazoharafiahaiqa";
    
    // This method use to encrypt the string
    public static String encrypt(String strToEncrypt)
    {
        try 
        {
            // Create default byte array
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);
  
            // Create SecretKeyFactory object
            SecretKeyFactory factory = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA256");
            
            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec
            (
                SECRET_KEY.toCharArray(), SALT.getBytes(),
                65536, 256);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec
                (
                tmp.getEncoded(), "AES");
  
                Cipher cipher = Cipher.getInstance
                (
                    "AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
                    // Return encrypted string
                    return Base64.getEncoder().encodeToString(
                 cipher.doFinal(strToEncrypt.getBytes(
              StandardCharsets.UTF_8)));
        }
        catch (Exception e) 
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    
     // This method use to decrypt the string
    public static String decrypt(String strToDecrypt)
    {
        try 
        {
            // Default byte array
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0 };
            // Create IvParameterSpec object and assign with
            // constructor
            IvParameterSpec ivspec= new IvParameterSpec(iv);
  
            // Create SecretKeyFactory Object
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
  
            // Create KeySpec object and assign with
            // constructor
            KeySpec spec = new PBEKeySpec
            (
                SECRET_KEY.toCharArray(), SALT.getBytes(),65536, 256);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec
                (
                    tmp.getEncoded(), "AES");

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
                    // Return decrypted string
                    return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e) 
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
    
    
    public static String generateSHA256(String message) throws Exception {
        return hashString(message, "SHA-256");
    }
 
    private static String hashString(String message, String algorithm)
            throws Exception {
 
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashedBytes = digest.digest(message.getBytes("UTF-8"));
 
            return convertByteArrayToHexString(hashedBytes);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            throw new Exception(
                    "Could not generate hash from String", ex);
        }
    }
 
    private static String convertByteArrayToHexString(byte[] arrayBytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < arrayBytes.length; i++) {
            stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16)
                    .substring(1));
        }
        return stringBuffer.toString();
    }

    
    public static void main(String[] args) throws Exception
    {
        System.out.println("Waiting for data packets from client: "); 
        ServerSocket ss=new ServerSocket(3333);  
        Socket s=ss.accept();  
        DataInputStream din=new DataInputStream(s.getInputStream());
        DataOutputStream dout=new DataOutputStream(s.getOutputStream()); 
        BufferedReader br=new BufferedReader(new InputStreamReader(System.in));  
        String str,msg,decryptedString,encrypted_msg,encrypted_hash, decrypted_hash, hash1, hash2="";
        while(true)
        {
            str=din.readUTF();
            hash1=din.readUTF();
            //Call decryption method
            decryptedString = AES_Server.decrypt(str);
            System.out.println("Client Says: "+str);
            System.out.println("Decrypted Data: "+decryptedString);
            decrypted_hash = AES_Server.decrypt(hash1);  //decrypt recieved hash
            String hash3 = generateSHA256(decryptedString);  //calculated hash of recieved decrypted message
            if (!decrypted_hash.equals(hash3))
            {
                System.out.println("Terminating Communication with the Server as Integrity is NOT Maintained");
                break;
            }
            System.out.println("Integrity Maintained!");
            if(decryptedString.equals("stop"))
            {
                System.out.println("Terminating Communication with the Client");
                break;
            }
            //Sending Response to Client
            System.out.println();
            System.out.println("Enter a Message: ");
            msg=br.readLine();  
            
            //Call hashing method
            hash2 = generateSHA256(msg);                     //generating hash
                   
            //Call encryption method
            encrypted_msg= AES_Server.encrypt(msg);
            encrypted_hash= AES_Server.encrypt(hash2);    //encrypting hash
            dout.writeUTF(encrypted_msg);
            dout.writeUTF(encrypted_hash);
            dout.flush(); 
            
            //If stop is entered, end the communication
            if(msg.equals("stop"))
            {
                System.out.println("Terminating Communication with the Client");
                break;
            }
            System.out.println("Encrypted Message: "+encrypted_msg);  
            System.out.println("\n");
        }
        din.close();  
        s.close(); 
        ss.close();
    }
}
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.phuccom.assignmentcrypt.utils;

import com.phuccom.assignmentcrypt.UpdateStatusCallback;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.DESKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * Utility class for encryption/decryption files
 * @author bbphuc
 */
public class FileEncryption {
    private Cipher aesCipher;
    private UpdateStatusCallback mCallback;
    private Key key;
    private SecretKey mKey;
    
    private long totalInputFileSize;
    private long remain;
    private long totalOutputFileSize;
    
    public static class InvalidChecksum extends Exception {
        
    }
    
    public void setKey(SecretKey key){
        this.mKey = key;
    }

    public FileEncryption(UpdateStatusCallback callback) {
        this.mCallback = callback;
    }
    
    
    
    /**
     * Encrypts and then copies the contents of a given file.
     * @param in input file for encryption 
     * @param out
     * @throws FileNotFoundException
     * @throws IOException 
     * @throws java.security.InvalidKeyException 
     * @throws com.phuccom.assignmentcrypt.utils.FileEncryption.InvalidChecksum 
     */
    public void encrypt(File in, File out) throws FileNotFoundException, IOException, InvalidKeyException, InvalidChecksum {
        encryptOrDecrypt(in, out, Cipher.ENCRYPT_MODE);
    }
    public void decrypt(File in, File out) throws IOException, FileNotFoundException, InvalidKeyException, InvalidChecksum {
        encryptOrDecrypt(in, out, Cipher.DECRYPT_MODE);
    }
    
    private void encryptOrDecrypt(File in, File out, int type) throws FileNotFoundException, IOException, InvalidKeyException, InvalidChecksum 
    {
        totalInputFileSize =  in.length();
        remain = totalInputFileSize;
        try {
            //String password = "something";
            //DESKeySpec dks = new DESKeySpec(password.getBytes());
            //SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            SecretKey desKey = mKey;
            
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            
            
            if (type == Cipher.ENCRYPT_MODE){
                // Encrypt with file checksum
                
                byte[] checksum = getFileChecksum(in);
                
                cipher.init(Cipher.ENCRYPT_MODE, desKey);
                CipherOutputStream os;
                try (FileInputStream is = new FileInputStream(in)) {
                    os = new CipherOutputStream(new FileOutputStream(out), cipher);
                    // Write file checksum first
                    byte[] buff = Arrays.copyOf(checksum, 1024);
                    System.out.println(DatatypeConverter.printHexBinary(buff));
                    os.write(buff);
                    copy(is, os);
                }
                os.close();
            }
            if (type == Cipher.DECRYPT_MODE){
                cipher.init(Cipher.DECRYPT_MODE, desKey);
                
                FileOutputStream os;
                byte[] checksum;
                try (CipherInputStream is = new CipherInputStream(new FileInputStream(in), cipher)) {
                    os = new FileOutputStream(out);
                    // Read checksum first
                    byte[] buff = new byte[1024];
                    int read = 0;
                    int index = 0;
                    int len = 1024;
                    while (len > 0){
                        read = is.read(buff, index, len);
                        System.out.println("read : " + read);
                        index += read;
                        len -= read;
                    }
                    
                    checksum = buff;
                    System.out.println(DatatypeConverter.printHexBinary(buff));
                    copy(is, os);
                }
                os.close();
                
                // Run message digest to check file
                byte[] out_cs = Arrays.copyOf(getFileChecksum(out), 1024);
                if (!Arrays.equals(checksum, out_cs)){
                    throw new InvalidChecksum();
                }
            }
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(FileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void copy(InputStream is, OutputStream os) throws IOException{
        int i;
        byte[] buffer = new byte[1024];
        boolean isFirst = true;
        int j = 0;
        while ((i = is.read(buffer)) != -1){
            if (j < 2){
                System.out.println(DatatypeConverter.printHexBinary(buffer));
                j++;
            }
            os.write(buffer, 0, i);
            remain = remain - i;
            mCallback.update((remain) / (float)totalInputFileSize);
        }
    }
    
    public static byte[] getFileChecksum(File file) throws FileNotFoundException, IOException{
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            DigestInputStream dis = new DigestInputStream(new FileInputStream(file), digest);
            byte[] buffer = new byte[1024];
            int r = dis.read(buffer);
            while (r > -1){
                r = dis.read(buffer);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(FileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}

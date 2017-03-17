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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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

/**
 * Utility class for encryption/decryption files
 * @author bbphuc
 */
public class FileEncryption {
    private Cipher aesCipher;
    private UpdateStatusCallback mCallback;
    private Key key;
    
    private long totalInputFileSize;
    private long remain;
    private long totalOutputFileSize;

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
     */
    public void encrypt(File in, File out) throws FileNotFoundException, IOException, InvalidKeyException {
        encryptOrDecrypt(in, out, Cipher.ENCRYPT_MODE);
    }
    public void decrypt(File in, File out) throws IOException, FileNotFoundException, InvalidKeyException {
        encryptOrDecrypt(in, out, Cipher.DECRYPT_MODE);
    }
    
    private void encryptOrDecrypt(File in, File out, int type) throws FileNotFoundException, IOException, InvalidKeyException 
    {
        totalInputFileSize =  in.length();
        remain = totalInputFileSize;
        try {
            String password = "something";
            DESKeySpec dks = new DESKeySpec(password.getBytes());
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            SecretKey desKey = skf.generateSecret(dks);
            
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            
            
            if (type == Cipher.ENCRYPT_MODE){
                
                cipher.init(Cipher.ENCRYPT_MODE, desKey);
                FileInputStream is = new FileInputStream(in);
                CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), cipher);
                copy(is, os);
                is.close();
                os.close();
            }
            if (type == Cipher.DECRYPT_MODE){
                cipher.init(Cipher.DECRYPT_MODE, desKey);
                
                CipherInputStream is = new CipherInputStream(new FileInputStream(in), cipher);
                FileOutputStream os = new FileOutputStream(out);
                copy(is, os);
                is.close();
                os.close();
            }
            
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(FileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void copy(InputStream is, OutputStream os) throws IOException{
        int i;
        byte[] buffer = new byte[1024];
        while ((i = is.read(buffer)) != -1){
            os.write(buffer, 0, i);
            remain = remain - i;
            mCallback.update((remain) / (float)totalInputFileSize);
        }
    }
}

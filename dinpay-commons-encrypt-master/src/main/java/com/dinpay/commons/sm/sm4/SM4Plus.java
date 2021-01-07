package com.dinpay.commons.sm.sm4;

/**
 * Created by $(USER) on $(DATE)
 */


import org.bouncycastle.util.encoders.Base64;

import com.dinpay.commons.encrypt.itf.ISymmetricEncrypt;
import com.dinpay.commons.sm.Util;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SM4Plus implements ISymmetricEncrypt{

    public String secretKey = "";
    public String iv = "";
    public boolean hexString = false;

    public SM4Plus() {
    }
    
    public SM4Plus(String hexStrkey) {
    	this.secretKey = hexStrkey;
    	this.hexString = true;
    }


	/**
	 * 加密解密都使用ECB模式
	 */
	@Override
	public byte[] encrypt(byte[] clearBytes) throws Exception {
		// TODO Auto-generated method stub
		try {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            if (hexString) {
                keyBytes = Util.hexStringToBytes(secretKey);
            } else {
                //keyBytes = secretKey.getBytes();
                keyBytes = Util.hexStringToBytes(secretKey);
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, clearBytes);
            return encrypted;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
	}


	@Override
	public String encrypt(String clearStr) throws Exception {
		// TODO Auto-generated method stub
		try {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            if (hexString) {
                keyBytes = Util.hexStringToBytes(secretKey);
            } else {
                //keyBytes = secretKey.getBytes();
                keyBytes = Util.hexStringToBytes(secretKey);
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, clearStr.getBytes("UTF-8"));
            return Util.byteToHex(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
	}


	@Override
	public byte[] decrypt(byte[] encBytes) throws Exception {
		try {
            //byte[] encrypted = Util.hexToByte(encHexStr);
            String encHexStr = Base64.toBase64String(encBytes);
            //cipherText = new BASE64Encoder().encode(encrypted);
            if (encHexStr != null && encHexStr.trim().length() > 0) {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(encHexStr);
                encHexStr = m.replaceAll("");
            }

            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            if (hexString) {
                keyBytes = Util.hexStringToBytes(secretKey);
            } else {
                keyBytes = secretKey.getBytes();
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Base64.decode(encHexStr));
            //byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
            return decrypted;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
	}


	@Override
	public String decrypt(String encHexStr) throws Exception {
		try {
            byte[] encrypted = Util.hexToByte(encHexStr);
            encHexStr=Base64.toBase64String(encrypted);
            //cipherText = new BASE64Encoder().encode(encrypted);
            if (encHexStr != null && encHexStr.trim().length() > 0) {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(encHexStr);
                encHexStr = m.replaceAll("");
            }

            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            if (hexString) {
                keyBytes = Util.hexStringToBytes(secretKey);
            } else {
                keyBytes = secretKey.getBytes();
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Base64.decode(encHexStr));
            //byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            //return null;
            throw new Exception(e);
        }
	}
	
	 public static void main(String[] args) throws Exception {
	        String plainText = "15dac41ad6f74a7c88190c477db412ba";
	        String s = Util.byteToHex(plainText.getBytes());
	        System.out.println("原文" + s);
	        SM4Plus sm4 = new SM4Plus("19cd822a25b021e3b0219ef471490902");
	        //sm4.secretKey = "JeF8U9wHFOMfs2Y8";
	        //sm4.secretKey = "1d65bc8111cec912fe9f5a2ad89866e3";
	        //sm4.hexString = true;

	        System.out.println("ECB模式加密");
	        String cipherText = sm4.encrypt(plainText);
	        System.out.println("密文: " + cipherText);
	        System.out.println("");

	        //String cipherText ="0f4f03db1014ab7706869b8c2c6883926af7469297f5412e912eec726ac0dc3be88748e9bab2f0a1a8b620a4a6741c5b";
			//byte[] cipherText;
			String plainText2 = sm4.decrypt(cipherText);
	        System.out.println("明文: " + plainText2);
	        System.out.println("");

	      

	    }
	
}

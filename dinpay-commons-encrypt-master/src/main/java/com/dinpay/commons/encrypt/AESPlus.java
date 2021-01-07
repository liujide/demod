package com.dinpay.commons.encrypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.dinpay.commons.encrypt.itf.ISymmetricEncrypt;
import com.dinpay.commons.encrypt.utils.StringByteUtil;

/**
 * 
 * @ClassName: AESPlus
 * @Description: AES加解密处理类 
 * @author JiangJunMing 
 * @date 2017年7月31日 下午2:21:15 
 *  
 */
public class AESPlus implements ISymmetricEncrypt{

	private Cipher encCipher = null;
	private Cipher decCipher = null;
	
	private static final String DEFAULT_KEY = "YQdUo5ZHlw3zs3Joes8bgVpiS7hb9URx";
	
	public AESPlus() throws Exception {
		this(DEFAULT_KEY);
	}
	
	/**
	 * 
	 * <p>Title: </p> 
	 * <p>Description: 构造函数，初始化AES加解密器</p> 
	 * @param hexStrkey 十六进制字符串形式key
	 * @throws Exception 
	 */
	public AESPlus(String hexStrkey) throws Exception {
		byte[] encoded = StringByteUtil.hexStringToByteArray(hexStrkey);
		SecretKey secretKey = new SecretKeySpec(encoded, "AES");
		
		encCipher = Cipher.getInstance("AES");
		encCipher.init(Cipher.ENCRYPT_MODE, secretKey);
		
		decCipher = Cipher.getInstance("AES");
		decCipher.init(Cipher.DECRYPT_MODE, secretKey);
	}
	
	/**
	 * 
	 * @Title: encrypt 
	 * @Description: 加密
		* @param clearStr 明文串
		* @return String 十六进制密文串
		* @throws IllegalBlockSizeException
		* @throws BadPaddingException
	 */
	@Override
	public String encrypt(String clearStr) throws IllegalBlockSizeException, BadPaddingException {
		if (clearStr == null) {
			return null;	
		}
		byte[] clearBytes = clearStr.getBytes();
		byte[] result = encrypt(clearBytes);
		return StringByteUtil.byteArrayToHexString(result);

	}
	
	/**
	 * 
	 * @Title: encrypt 
	 * @Description: 加密
	 * @param clearBytes 明文字节
	 * @return byte[] 密文字节 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException 
	 */
	@Override
	public byte[] encrypt(byte[] clearBytes) throws IllegalBlockSizeException, BadPaddingException{
		if (clearBytes == null) {
			return null;
		}
		return encCipher.doFinal(clearBytes);
	}
	
	
	/**
	 * 
	 * @Title: decrypt 
	 * @Description: 解密 
		* @param encHexStr 十六进制明文字符串
		* @return String 明文字符串
		* @throws IllegalBlockSizeException
		* @throws BadPaddingException
	 */
	@Override
	public String decrypt(String encHexStr) throws IllegalBlockSizeException, BadPaddingException {
		String decStr = null;
		if (encHexStr == null) {
			return decStr;	
		}
		byte[] encBytes = StringByteUtil.hexStringToByteArray(encHexStr);
		byte[] result = decrypt(encBytes);
		decStr = new String(result); 
		return decStr;
	}
	
	/**
	 * 
	 * @Title: decrypt 
	 * @Description: 解密
		* @param encBytes 密文字节
		* @return byte[] 明文字节
		* @throws IllegalBlockSizeException
		* @throws BadPaddingException
	 */
	@Override
	public byte[] decrypt(byte[] encBytes) throws IllegalBlockSizeException, BadPaddingException{
		if (encBytes == null) {
			return null;
		}
		return decCipher.doFinal(encBytes);
	}
	
}

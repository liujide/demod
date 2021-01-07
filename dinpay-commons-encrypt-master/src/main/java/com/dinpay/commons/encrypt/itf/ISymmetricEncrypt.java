package com.dinpay.commons.encrypt.itf;

/**
 * 
 * @ClassName: ISymmetricEncrypt 
 * @Description: 对称加密接口
 * @author JiangJunMing 
 * @date 2017年7月31日 下午5:24:04 
 *  
 */
public interface ISymmetricEncrypt {

	/**
	 * 
	 * @Title: encrypt 
	 * @Description: 加密
	 * @param clearBytes 明文字节
	 * @return byte[] 密文字节 
	 * @throws Exception
	 */
	public byte[] encrypt(byte[] clearBytes) throws Exception;
	
	/**
	 * 
	 * @Title: encrypt 
	 * @Description: 加密
		* @param clearStr 明文串
		* @return String 十六进制密文串
		* @throws Exception
	 */
	public String encrypt(String clearStr) throws Exception;
	
	/**
	 * 
	 * @Title: decrypt 
	 * @Description: 解密
		* @param encBytes 密文字节
		* @return byte[] 明文字节
		* @throws Exception
	 */
	public byte[] decrypt(byte[] encBytes) throws Exception;
	
	/**
	 * 
	 * @Title: decrypt 
	 * @Description: 解密 
		* @param encHexStr 十六进制明文字符串
		* @return String 明文字符串
		* @throws Exception
	 */
	public String decrypt(String encHexStr) throws Exception;
}

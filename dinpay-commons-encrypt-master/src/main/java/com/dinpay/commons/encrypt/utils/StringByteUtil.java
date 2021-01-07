package com.dinpay.commons.encrypt.utils;

import java.util.zip.DataFormatException;

/**
 * 
 * @ClassName: StringByteUtil 
 * @Description: 字符字节转换工具类 
 * @author JiangJunMing 
 * @date 2017年7月25日 下午8:11:19 
 *  
 */
public class StringByteUtil {
	
	/**
	 * 
	 * @Title: byteArrayToHexString 
	 * @Description: 字节数组转换成16进制字符串 
	 * @param data 字节数组
	 * @return String 16进制字符串 
	 */
	public static String byteArrayToHexString(byte[] data) {
		if (data == null || data.length < 1) {
			return null;
		}
		StringBuilder sb = new StringBuilder(data.length * 2);
		for (byte b : data) {
			int v = b & 0xFF;
			if (v < 16) {
				sb.append('0');
			}
			sb.append(Integer.toHexString(v));
		}
		return sb.toString();
	}
	
	/**
	 * 
	 * @Title: hexStringToByteArray 
	 * @Description: 16进制字符串转换成字节数组
	 * @param hexStr 16进制字符串
	 * @return byte[] 字节数组
	 * @throws DataFormatException 
	 */
	public static byte[] hexStringToByteArray(String hexStr){
		if (hexStr == null || hexStr.trim().length() < 1) {
			return null;
		}
		int len = hexStr.length();
		byte[] b = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			// 两位一组，表示一个字节,把这样表示的16进制字符串，还原成一个字节
			b[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
					+ Character.digit(hexStr.charAt(i + 1), 16));
		}
		return b;
	}
}

package com.dinpay.commons.encrypt.utils;

/**
 * 
 * @ClassName: SensitiveDataUtil 
 * @Description: 敏感数据工具类
 * @author JiangJunMing 
 * @date 2017年8月12日 下午3:56:52 
 *  
 */
public class SensitiveDataUtil {

	/**
	 * 
	 * @Title: cardNoMask 
	 * @Description: 获取银行卡号掩码
		* @param cardNo
		* @return
	 */
	public static String cardNoMask(final String cardNo){
		if (cardNo == null || "".equals(cardNo.trim())) {
			return cardNo;
		}
		String number = cardNo.trim();
		int len = number.length();
		if (len >= 4) {
			number = "****"+number.substring(len-4, len);
		}else{
			number = "****"+number;
		}
		return number;
	}
	
	/**
	 * 
	 * @Title: mobileNoMask 
	 * @Description: 手机号掩码
		* @param mobileNo
		* @return
	 */
	public static String mobileNoMask(final String mobileNo){
		if (mobileNo == null || "".equals(mobileNo.trim())) {
			return mobileNo;
		}
		String number = mobileNo.trim();
		int len = number.length();
		if (len >= 6) {
			number = number.substring(0,3)+"***"+number.substring(len-3, len);
		}else if(len >= 3){
			number = number.substring(0, len-3)+"***"+number.substring(len-3, len);
		}else{
			number = "***"+number;
		}
		return number;
	}
}

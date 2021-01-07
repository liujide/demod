package com.dinpay.commons.encrypt.pci;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.dinpay.commons.encrypt.AESPlus;
import com.dinpay.commons.encrypt.Constants;
import com.dinpay.commons.encrypt.DESPlus;
import com.dinpay.commons.encrypt.EncAlgorithm;
import com.dinpay.commons.encrypt.exception.CryptoException;
import com.dinpay.commons.encrypt.itf.ISymmetricEncrypt;
import com.dinpay.commons.sm.sm4.SM4Plus;


/**
 * 
 * @ClassName: SymmetricEncryptFactory 
 * @Description: 对称加密算法（AES和DES）加密器工厂类，为了达到PCI要求，需要将DES加密方式整改为AES，同时也要为了兼容之前DES加密的数据，特此设计此类，
	*															它可以兼容多密钥，初始化加密器并提供统一的加解密方法symmetricEncrypt、symmetricDecrypt进行加解密。
 * @author JiangJunMing 
 * @date 2017年8月10日 下午2:15:39 
 *  
 */
public class SymmetricEncryptFactory {

	private static Log log = LogFactory.getLog(SymmetricEncryptFactory.class);
	private Map<String, ISymmetricEncrypt> symmetricEncrypts = null;

	private String defaultAESKeyIndex = null;  //AES加解密默认密钥索引
	private String desKeyIndex = null;  //DES密钥索引
	private String defaultSM4KeyIndex = null;  //SM4加解密默认密钥索引

	/**
	 * 
	 * <p>Description: 构造函数</p> 
	 * @param desKeyIndex	DES密钥索引，PCI改造前用DES算法进行数据加解密用的密钥
	 * @param kekValue	KEK值
	 * @param dekMap DEK键值对（keyIndex，keyValue），密钥表中目前在使用的所有AES和DES密钥
	 * @throws Exception 
		 */
	public SymmetricEncryptFactory(String desKeyIndex, String kekValue, Map<String, String> dekMap) throws Exception{
		
		//log.info("-======sm4 key========"+dekMap.get("1003")+"========kekValue==="+kekValue);
		symmetricEncrypts = new HashMap<String, ISymmetricEncrypt>();
		//检查数据合法性
		if (desKeyIndex == null || "".equals(desKeyIndex.trim()) || kekValue == null
			|| "".equals(kekValue.trim()) || dekMap == null || dekMap.size() == 0) {
			throw new CryptoException("init params is empty.");
		}
		String[]	dekValues = null;
		
		String desKeyValue = dekMap.get(desKeyIndex);
		if (desKeyValue == null) {
			throw new CryptoException("desKeyIndex doesn't have value in dekMap.");
		}
		dekValues = desKeyValue.split("&");
		if (!EncAlgorithm.DES.getStatus().equals(dekValues[0])) {
			throw new CryptoException("desKeyIndex isn't DES key index.");
		}
		
		//初始化KEK加密器
		AESPlus kekAESPlus = new AESPlus(kekValue);
		SM4Plus kekSM4Plus = new SM4Plus(kekValue);
		
		//初始化DES加密器，并加入到内存里
		DESPlus desPlus = new DESPlus(kekAESPlus.decrypt(dekValues[1]));
		symmetricEncrypts.put(desKeyIndex, desPlus);
		this.desKeyIndex = desKeyIndex;
		
		//初始化AES加密器，并选择最新的密钥（过期时间最后的）作为默认加密密钥
		Date latestTime = null;
		Date sm4LatestTime = null;
		Set<String> keyIndexs = dekMap.keySet();
		for (String keyIndex : keyIndexs) {
			String dekValue = dekMap.get(keyIndex);
			dekValues = dekValue.split("&");
			if (dekValues.length != 3) {	//values的格式为ENC_ALGORITHM&KEY_VALUE&EXPIRE_TIME
				throw new CryptoException("The format of dekValue isn't like that: 'ENC_ALGORITHM&KEY_VALUE&EXPIRE_TIME'.");
			}
			
			//初始化加密器，存于内存当中
			if(EncAlgorithm.AES.getStatus().equals(dekValues[0])){
				//主密钥解密加密密钥
				String keyValue = kekAESPlus.decrypt(dekValues[1]);		
				AESPlus aesPlus = new AESPlus(keyValue);
				
				//选举过期日期最后的AES密钥索引作为当前加密用的默认密钥
				Date expireTime = new Date(Long.parseLong(dekValues[2]));
				if (latestTime == null) {
					latestTime = expireTime;
					defaultAESKeyIndex = keyIndex;
				}else if(latestTime.before(expireTime)){
					latestTime = expireTime;
					defaultAESKeyIndex = keyIndex;
				}
				
				symmetricEncrypts.put(keyIndex, aesPlus);
			}
			
			//初始化加密器，存于内存当中
			if(EncAlgorithm.SM4.getStatus().equals(dekValues[0])){
				String keyValue = kekSM4Plus.decrypt(dekValues[1]);		
				
				SM4Plus sM4Plus = new SM4Plus(keyValue);   
			    //log.info(keyValue+"-======sm4 key========"+dekValues[0]+"===="+dekValues[1]+"==="+dekValues[2]);
				
				//选举过期日期最后的AES密钥索引作为当前加密用的默认密钥
				Date expireTime = new Date(Long.parseLong(dekValues[2]));
				if (sm4LatestTime == null) {
					sm4LatestTime = expireTime;
					defaultSM4KeyIndex = keyIndex;
				}else if(latestTime.before(expireTime)){
					latestTime = expireTime;
					defaultSM4KeyIndex = keyIndex;
				}
				
				symmetricEncrypts.put(keyIndex, sM4Plus);
			}
			
		}
	}
	
	/**
	 * 
	 * @Title: symmetricEncrypt 
	 * @Description: 加密
		* @param plainText 明文
		* @param isDES 是否用以前的DES密钥加密，否则用最新的AES密钥进行加密
		* @return String  密文
		* @throws Exception
	 */
	public String symmetricEncrypt(final String plainText, boolean isDES) throws Exception{
		String cipherText = plainText;		
		if (cipherText != null) {
			if (isDES) {
				ISymmetricEncrypt symmetricEncrypt = symmetricEncrypts.get(desKeyIndex);
				try {
					symmetricEncrypt.decrypt(cipherText);		//先尝试解密，如果失败，则说明字符串是未加密的
				} catch (Exception e) {
					cipherText = symmetricEncrypt.encrypt(cipherText);
				}	
			}else{
				ISymmetricEncrypt symmetricEncrypt = symmetricEncrypts.get(defaultAESKeyIndex);
				try {
					symmetricEncrypt.decrypt(cipherText);		//先尝试解密，如果失败，则说明字符串是未加密的
				} catch (Exception e) {
					symmetricEncrypt = symmetricEncrypts.get(defaultSM4KeyIndex);
					if(cipherText.length() < 32) {
						cipherText = symmetricEncrypt.encrypt(plainText);
						cipherText += Constants.ENC_SPLIT_SYMBOL+defaultSM4KeyIndex; //默认用sm4加密
					}else {
						try {
							symmetricEncrypt.decrypt(plainText);		//先尝试解密,如果是sm4加密的也直接返回
						}catch (Exception e1) {
						cipherText = symmetricEncrypt.encrypt(plainText);
						cipherText += Constants.ENC_SPLIT_SYMBOL+defaultSM4KeyIndex; //默认用sm4加密
						//return cipherText;
					    }
					}
			}
			}
		}
	 return cipherText;
	}
	
	/**
	 * 加密
	 * @param plainText 明文
	 * @param EncAlgorithmStatus 根据EncAlgorithm获取枚举
	 * @return String 密文
	 * @throws Exception
	 */
	public String symmetricEncrypt(final String plainText, String encAlgorithmStatus) throws Exception {
		String cipherText = plainText;
		if (cipherText != null) {
			if (EncAlgorithm.DES.getStatus().equals(encAlgorithmStatus)) {
				ISymmetricEncrypt symmetricEncrypt = symmetricEncrypts.get(desKeyIndex);
				try {
					symmetricEncrypt.decrypt(cipherText);		//先尝试解密，如果失败，则说明字符串是未加密的
				} catch (Exception e) {
					cipherText = symmetricEncrypt.encrypt(cipherText);
				}	
			}else if(EncAlgorithm.AES.getStatus().equals(encAlgorithmStatus)){
				ISymmetricEncrypt symmetricEncrypt = symmetricEncrypts.get(defaultAESKeyIndex);
				try {
					symmetricEncrypt.decrypt(cipherText);		//先尝试解密，如果失败，则说明字符串是未加密的
				} catch (Exception e) {
					cipherText = symmetricEncrypt.encrypt(cipherText);
					cipherText += Constants.ENC_SPLIT_SYMBOL+defaultAESKeyIndex;
				}
			}else if(EncAlgorithm.SM4.getStatus().equals(encAlgorithmStatus)){
				ISymmetricEncrypt symmetricEncrypt = symmetricEncrypts.get(defaultSM4KeyIndex);
				if(cipherText.length() > 31) {
					try {
						symmetricEncrypt.decrypt(cipherText);		//先尝试解密，如果失败，则说明字符串是未加密的
					} catch (Exception e) {
						cipherText = symmetricEncrypt.encrypt(cipherText);				
						cipherText += Constants.ENC_SPLIT_SYMBOL+defaultSM4KeyIndex;
					}
				}else {
					cipherText = symmetricEncrypt.encrypt(cipherText);				
					cipherText += Constants.ENC_SPLIT_SYMBOL+defaultSM4KeyIndex;
				}
			}else {
				return null;
			}
		}
	 return cipherText;
	}
	
	
	
	/**
	 * 
	 * @Title: symmetricEncrypt 
	 * @Description: 用最新的AES密钥进行加密
		* @param plainText 明文
		* @return String  密文
		* @throws Exception
	 */
	public String symmetricEncrypt(final String plainText) throws Exception{
		return symmetricEncrypt(plainText, false);
	}
	
	/**
	 * 
	 * @Title: symmetricDecrypt 
	 * @Description: 解密
		* @param cipherText 密文
		* @return String  明文
		* @throws Exception
	 */
	public String symmetricDecrypt(final String cipherText) throws Exception{
		String plainText = cipherText;
		if(plainText != null){
			//PCI整改后，数据库表中的“加密存储字段值”会有两种表现方式：
			//第一种：加密存储字段值=加密串，这种方式，默认的密钥索引为1000，采用的是以前的DES加密算法；
			//第二种：加密存储字段值=加密串$密钥索引，这种方式是适合更换密钥，采用的是AES加密算法。
			int index = cipherText.lastIndexOf(Constants.ENC_SPLIT_SYMBOL);
			String keyIndex = null;
			if (index > -1) {		//第二种存储方式
				plainText = cipherText.substring(0, index);
				keyIndex = cipherText.substring(index+1, cipherText.length());
			}else{		//第一种存储方式
				keyIndex = desKeyIndex;
			}
			ISymmetricEncrypt symmetricEncrypt = symmetricEncrypts.get(keyIndex);
			plainText = symmetricEncrypt.decrypt(plainText);
		}
		return plainText;
	}
	
	


	/**
	 * 
	 * @Title: encryptWithAllOfKeys 
	 * @Description: 使用所有加密密钥加密
		* @param plainText	明文
		* @return List<String> 所有加密密钥加密的密文列表
		* @throws Exception
	 */
	public List<String> encryptWithAllOfKeys(final String plainText) throws Exception{
		if(plainText != null){
			Set<String> keySet = new HashSet<String>(symmetricEncrypts.keySet());
			keySet.remove(desKeyIndex);
			List<String> cipherTexts = new ArrayList<String>(keySet.size());
			String cipherText = null;
			//所有AES、SM4密钥加密
			for (String key : keySet) {
				ISymmetricEncrypt symmetricEncrypt = symmetricEncrypts.get(key);
				try {
					symmetricEncrypt.decrypt(plainText);		//先尝试解密，如果失败，则说明字符串是未加密的
				} catch (Exception e) {
					cipherText = symmetricEncrypt.encrypt(plainText);
					cipherText += Constants.ENC_SPLIT_SYMBOL+key;
				}
				cipherTexts.add(cipherText);
		 }
			//DES密钥加密
			ISymmetricEncrypt symmetricEncrypt = symmetricEncrypts.get(desKeyIndex);
			try {
				symmetricEncrypt.decrypt(plainText);		//先尝试解密，如果失败，则说明字符串是未加密的
			} catch (Exception e) {
				cipherText = symmetricEncrypt.encrypt(plainText);
			}
			cipherTexts.add(cipherText);
			return cipherTexts;
		}else{
			return null;
		}//end
	}
	
}

package com.dinpay.commons.encrypt.rsa;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;

import org.bouncycastle.util.encoders.Base64;

import com.itrus.cert.X509Certificate;
import com.itrus.cryptorole.CryptoException;
import com.itrus.cryptorole.NotSupportException;
import com.itrus.cryptorole.Recipient;
import com.itrus.cryptorole.bc.RecipientBcImpl;
import com.itrus.cryptorole.bc.SenderBcImpl;
import com.itrus.svm.SignerAndEncryptedDigest;
import com.itrus.util.DERUtils;
import com.itrus.util.FileUtils;

/**
 * 文件证书RSA方式
 * 
 * @author lzg
 * 
 */
public class MerchantRSAWithHardware {
	/**
	 * 服务端签名工具对象
	 */
	private SenderBcImpl signSenderBc;

	/**
	 * 服务端加密工具对象
	 */
	private SenderBcImpl encryptSenderBc;

	/**
	 * 客户端解密工具对象
	 */
	private Recipient decryptrecipient;
	
	private RecipientBcImpl recipient = new RecipientBcImpl();

	/**
	 * 智付证书校验信息
	 */
	private String DINPAY_CN = "E=tsm@ddbill.com, CN=DINPAY001, OU=技术部, O=智付电子支付有限公司";
	
	private static File versionFile = null;
	
	private static String DINPAY_KEY_VERSION;
	
	/**
	 * 初始化签名工具对象（需要签名时使用）
	 * 
	 * @param pfxFileName
	 *            pfx文件位置
	 * @param pfxPass
	 *            pfx文件密码
	 * @throws NotSupportException
	 * @throws CryptoException
	 */
	public void initSigner(String pfxFilePath, String pfxPass) throws Exception {
		// 初始化私钥加密对象
		signSenderBc = new SenderBcImpl();
		char[] pfxPassChars = pfxPass.toCharArray();
		signSenderBc.initCertWithKey(pfxFilePath, pfxPassChars);
		signSenderBc.setSignAlgorithm("SHA1WithRSA");
		//初始化对dinpay证书版本校验
		versionFile = new File(new File(pfxFilePath).getParentFile(),"dinpayRSAKeyVersion");
		if(versionFile.exists()){
			DINPAY_KEY_VERSION = new BufferedReader(new FileReader(versionFile)).readLine();
		}else {
			versionFile.createNewFile();
		}
	}

	/**
	 * 初始化加密对象（需要加密时使用）
	 * 
	 * @param cerFilePath
	 * @throws IOException
	 * @throws CertificateException
	 */
	public void initEncrypter(String cerFilePath) throws IOException, CertificateException {
		String pkCert = new String(Base64.encode(FileUtils.readBytesFromFile(cerFilePath)));
		pkCert = pkCert.replace("\n", "");
		X509Certificate certificate = X509Certificate.getInstance(pkCert);
		encryptSenderBc = new SenderBcImpl();
		encryptSenderBc.addRecipientCert(certificate);
	}

	/**
	 * 初始化客户端解密对象（需要解密时使用）
	 * 
	 * @param pfxFilePath
	 * @param pfxPass
	 * @throws NotSupportException
	 * @throws CryptoException
	 */
	public void initDecrypter(String pfxFilePath, String pfxPass) throws NotSupportException, CryptoException {
		decryptrecipient = new RecipientBcImpl();
		decryptrecipient.initCertWithKey(pfxFilePath, pfxPass.toCharArray());
	}

	/**
	 * 签名方法
	 * 
	 * @param plainText
	 * @return
	 */
	public String signByPriKey(String plainText) {
		try {
			String hex = DERUtils.BytesToHexString(plainText.getBytes("UTF-8"));
			byte[] signedData = signSenderBc.signMessage(hex.getBytes("UTF-8"));
			return new String(Base64.encode(signedData));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 验证签名-公钥验证（商家pfx文件中证书的CN = 商家传入merchantID值 报文中证书CN包含的商户号=智付CN）
	 * 
	 * @param merchantId
	 * @param parmaStr
	 * @param signedData
	 * @return
	 */
	public boolean validateSignByPubKey(String merchantId, String parmaStr, String signedData) {
		try {
			// 校验签名
			String hex = DERUtils.BytesToHexString(parmaStr.getBytes("UTF-8"));
			byte[] signedDataBytes = Base64.decode(signedData);
			SignerAndEncryptedDigest digest = recipient.verifyAndParsePkcs7(hex.getBytes("UTF-8"), signedDataBytes);
			X509Certificate certificate = X509Certificate.getInstance(digest.getSigner());
			DERUtils.HexStringToBytes(new String(digest.getOriData()));
			String ciphertextMerchantInfo = certificate.getSubjectDNString();
			// 判断消息是否从dinpay发出
			if (!ciphertextMerchantInfo.startsWith(DINPAY_CN)) {
				throw new RuntimeException("validate sign failed:this message is not sended from dinpay.");
			}
			
			//校验dinpay证书版本号
			checkDinpayKeyVersion(ciphertextMerchantInfo);
			
			// 从商户pfx证书中获取商户号
			java.security.cert.X509Certificate merchantCe = signSenderBc.getSignerCert();
			String pfxMerchantInfo = merchantCe.getSubjectX500Principal().getName();
			String pfxMerchantCode = pfxMerchantInfo.substring(pfxMerchantInfo.indexOf("CN=") + 3);
			if (pfxMerchantCode.contains(",")) {
				pfxMerchantCode = pfxMerchantCode.substring(0, pfxMerchantCode.indexOf(","));
			}
			// 比较商户号
			if (!merchantId.equals(pfxMerchantCode)) {
				throw new RuntimeException("validate sign failed:merchant_code is not equal.merchant_code in pfx is " + pfxMerchantCode + ",but merchant_code in params is " + merchantId);
			}
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	/**
	 * 使用Dinpay公钥加密
	 * 
	 * @param plainText
	 * @return
	 */
	public String encryptByPubKey(String plainText) {
		try {
			byte[] txt = Base64.encode(encryptSenderBc.encryptMessage(plainText.getBytes("UTF-8")));
			String encodeMsg = new String(txt, "utf-8");
			return encodeMsg;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 使用自身私钥解密
	 * 
	 * @param encyptedData
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws NotSupportException
	 * @throws CryptoException
	 */
	public String decryptByPrikey(String encyptedData) throws UnsupportedEncodingException, NotSupportException, CryptoException {
		String decodeString = new String(decryptrecipient.decryptMessage(Base64.decode(encyptedData.getBytes("utf-8"))));
		return decodeString;
	}
	
	private static void checkDinpayKeyVersion(String ciphertextMerchantInfo){
		//校验dinpay证书版本OU = V:1.0.0.1
		String dinpayKeyVersion = null;
		if(ciphertextMerchantInfo.indexOf("OU=V:")>0){
			dinpayKeyVersion = ciphertextMerchantInfo.substring(ciphertextMerchantInfo.indexOf("OU=V:")+5);
		}
		//已经存在版本，则与当前版本比较，若报文证书版本小于当前版本，则校验失败，等于则校验成功，大于则更新证书版本
		//若当前版本不存在，判断证书报文是否存在，若存在则更新证书版本，否则校验成功
		if(null != DINPAY_KEY_VERSION && !"".equals(DINPAY_KEY_VERSION.trim())) {
			if(null == dinpayKeyVersion || "".equals(dinpayKeyVersion.trim())){
				//dinpay证书版本过时
				throw new RuntimeException("dinpayKey version has outdated!");
			}
			dinpayKeyVersion = dinpayKeyVersion.trim();
			int compairResult = DINPAY_KEY_VERSION.compareTo(dinpayKeyVersion);
			if(compairResult>0) {
				//dinpay证书版本过时
				throw new RuntimeException("dinpayKey version has outdated!");
			}
			if(compairResult<0) {
				//更新版本信息
				FileWriter fw = null;
				try {
					fw = new FileWriter(versionFile);
					fw.write(dinpayKeyVersion);
					fw.flush();
				} catch (IOException e) {
					e.printStackTrace();
				}finally{
					try {
						if(null != fw) {
							fw.close();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}else {
			if(null != dinpayKeyVersion && !"".equals(dinpayKeyVersion.trim())){
				dinpayKeyVersion = dinpayKeyVersion.trim();
				//更新版本信息
				FileWriter fw = null;
				try {
					fw = new FileWriter(versionFile);
					fw.write(dinpayKeyVersion);
					fw.flush();
				} catch (IOException e) {
					e.printStackTrace();
				}finally{
					try {
						if(null != fw) {
							fw.close();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}
	}
}
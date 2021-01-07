package com.dinpay.commons.encrypt.rsa;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Base64;

import com.itrus.cert.X509Certificate;
import com.itrus.cryptorole.CryptoException;
import com.itrus.cryptorole.NotSupportException;
import com.itrus.cryptorole.Recipient;
import com.itrus.cryptorole.bc.RecipientBcImpl;
import com.itrus.cryptorole.bc.SenderBcImpl;
import com.itrus.cvm.CVM;
import com.itrus.svm.SignerAndEncryptedDigest;
import com.itrus.util.DERUtils;
import com.itrus.util.FileUtils;

/**
 * 文件证书RSA方式
 * 
 * @author lzg
 * 
 */
public class DinpayRSAWithHardware {
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

	private String cvmFilePath;

	private static Log log = LogFactory.getLog(DinpayRSAWithHardware.class);

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
	public void initSigner(String pfxFilePath, String pfxPass) throws NotSupportException, CryptoException {
		// 初始化私钥加密对象
		signSenderBc = new SenderBcImpl();
		char[] pfxPassChars = pfxPass.toCharArray();
		signSenderBc.initCertWithKey(pfxFilePath, pfxPassChars);
		signSenderBc.setSignAlgorithm("SHA1WithRSA");

	}

	public void initValidater(String cvmFilePath) {
		this.cvmFilePath = cvmFilePath;
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
			log.error(e.getMessage(), e);
		}
		return null;
	}

	/**
	 * dinpay验证签名（报文中证书CN包含的商户号 = 传入merchantId值）
	 * 
	 * @param parmaStr
	 * @param signedData
	 * @return
	 */
	public boolean validateSignByPubKey(String merchantId, String parmaStr, String signedData) {
		try {
			// 签名验证
			String hex = DERUtils.BytesToHexString(parmaStr.getBytes("UTF-8"));
			byte[] signedDataBytes = Base64.decode(signedData);
			SignerAndEncryptedDigest digest = recipient.verifyAndParsePkcs7(hex.getBytes("UTF-8"), signedDataBytes);
			X509Certificate certificate = X509Certificate.getInstance(digest.getSigner());
			if (null != cvmFilePath || "".equals(cvmFilePath)) {
				// 验证证书是否可用
				int ret = CVM.VALID;
				boolean cvmFlag = true;
				try {
					CVM.config(cvmFilePath);// 只会被初始化一次
					ret = CVM.verifyCertificate(certificate);
					if (ret != CVM.VALID) {
						switch (ret) {
						case CVM.CVM_INIT_ERROR:
							log.error("CVM初始化错误，请检查配置文件或给CVM增加支持的CA。");
							break;
						case CVM.CRL_UNAVAILABLE:
							log.error("CRL不可用，未知状态。");
							break;
						case CVM.EXPIRED:
							cvmFlag = false;
							throw new RuntimeException("证书已过期。");
						case CVM.ILLEGAL_ISSUER:
							cvmFlag = false;
							throw new RuntimeException("非法颁发者。");
						case CVM.REVOKED:
							cvmFlag = false;
							throw new RuntimeException("证书已吊销。");
						case CVM.UNKNOWN_ISSUER:
							log.error("不支持的颁发者，请检查cvm.xml配置文件。");
						case CVM.REVOKED_AND_EXPIRED:
							cvmFlag = false;
							throw new RuntimeException("证书被吊销且已过期。");
						}
					}
				} catch (Exception e) {
					if (!cvmFlag) {
						throw e;
					}
				}
			}
			DERUtils.HexStringToBytes(new String(digest.getOriData()));
			String ciphertextMerchantInfo = certificate.getSubjectDNString();
			// 从密文中获取证书和商户号
			String ciphertextMerchantCode = ciphertextMerchantInfo.substring(ciphertextMerchantInfo.indexOf("CN=") + 3);
			if (ciphertextMerchantCode.contains(",")) {
				ciphertextMerchantCode = ciphertextMerchantCode.substring(0, ciphertextMerchantCode.indexOf(","));
			}
			if (!ciphertextMerchantCode.equals(merchantId)) {
				throw new RuntimeException("validate sign failed:merchant_code is not equal.merchant_code in ciphertext is " + ciphertextMerchantCode + ",but merchantId is " + merchantId);
			}
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	/**
	 * 使用商家公钥加密
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
}
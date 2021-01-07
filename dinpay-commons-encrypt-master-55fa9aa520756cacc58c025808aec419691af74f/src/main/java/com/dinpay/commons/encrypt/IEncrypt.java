package com.dinpay.commons.encrypt;

public interface IEncrypt {
	
	public String encrypt(String plainText) throws Exception;
	
	public String decrypt(String cipherText) throws Exception ;

}

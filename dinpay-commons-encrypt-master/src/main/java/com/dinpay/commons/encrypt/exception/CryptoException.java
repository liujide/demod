package com.dinpay.commons.encrypt.exception;

public class CryptoException extends RuntimeException{

	private static final long serialVersionUID = 1162378681275237689L;

	protected String errorCode;

	public CryptoException(String errorCode) {
		super(errorCode);
		this.errorCode=errorCode;
	}
	
	public CryptoException(String errorCode,String message) {
		super(message);
		this.errorCode=errorCode;
	}

	public CryptoException(String errorCode,String message, Throwable cause) {
		super(message, cause);
		this.errorCode=errorCode;
	}

	public CryptoException(String errorCode,Throwable cause) {
		super(cause);
		this.errorCode=errorCode;
	}

	public String getErrorCode() {
		return errorCode;
	}
}

package com.dinpay.commons.encrypt;

/**
 * 
 * @ClassName: EncAlgorithm 
 * @Description: 加密算法枚举类
 * @author JiangJunMing 
 * @date 2017年8月10日 下午3:01:06 
 *  
 */
public enum EncAlgorithm {
  DES("1","DES"),
  AES("2","AES"),
  RSA("3","RSA"),
  MD5("4","MD5"),
  SHA("5","SHA"),
  SM4("6","SM4");
  private String status;
  private String desc;
  
  public String getStatus() {
      return status;
  }

  public String getDesc() {
      return desc;
  }
  
  private EncAlgorithm(String status, String desc) {
      this.status = status;
      this.desc   = desc;
  }

}

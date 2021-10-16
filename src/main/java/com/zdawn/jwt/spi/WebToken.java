package com.zdawn.jwt.spi;

import java.util.Map;

/**
 * token接口
 * @author zhaobs
 */
public interface WebToken {
	/**
	 * 获取jwt token，获取失败抛出异常
	 * @param uid 身份标识
	 * @param type token类型  metering计次 or timekeeping计时
	 * @return jwt token
	 */
	public String getJwtToken(String uid,String type) throws Exception;
	/**
	 * 验证jwt token，验证失败抛出异常
	 * @param jwtToken token
	 * @return uid 身份标识
	 */
	public String verifyJwtToken(String jwtToken) throws Exception;
	/**
	 * 清理过期Token
	 */
	public void clearExpireToken();
	/**
	 * 获取公钥 base64编码等配置信息
	 */
	public Map<String,String> getTokenConfig();
	/**
	 * 设置公钥信息
	 */
	public void setTokenConfig(Map<String, String> config);
	/**
	 * 验证获取jwt验证公钥的密码
	 */
	public boolean validateSecurityKeyForPublicKey(String securityKey);
	/**
	 * 验证配置配置参数
	 * 如果不合法抛出RuntimeException
	 */
	public void validateTokenConfig();
}

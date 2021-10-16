package com.zdawn.jwt.spi;

import java.util.List;

public interface TokenStore {
	/**
	 * token持久化
	 * @param token
	 */
	public void saveToken(Token token) throws Exception;
	
	/**
	 * 根据tokenId获取Token对象
	 * @param tokenId 唯一标识
	 */
	public Token queryTokenById(String tokenId) throws Exception;
	
	/**
	 * 根据用户标识查询Token集合
	 * @param userId 用户标识
	 */
	public List<Token> queryTokenByUserId(String userId) throws Exception;
	
	/**
	 * 更新Token对象
	 * @param token Token对象
	 */
	public void updateToken(Token token) throws Exception;
	
	/**
	 * 根据tokenId删除token对象
	 * @param tokenId 唯一标识
	 */
	public void delTokenById(String tokenId) throws Exception;
	
	/**
	 * 清理过期的token对象
	 * @param expireTime 过期时间 单位分钟
	 */
	public void clearTokenByOverTime(int expireTime) throws Exception;
	
	/**
	 * 过期Token移动到历史
	 * @param expireTime 过期时间 单位分钟
	 */
	public void moveHistoryTokenByOverTime(int expireTime) throws Exception;
	
	/**
	 * Token对象移动到历史
	 * @param tokenId
	 */
	public void moveHistoryToken(String tokenId) throws Exception;
	/**
	 * 验证配置参数  TokenStore是否支持 不支持抛出RuntimeException
	 * @param webToken
	 */
	public void validateTokenConfig(WebToken webToken);
}

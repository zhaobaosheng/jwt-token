package com.zdawn.jwt.spi;

/**
 * token数据项
 * @author zhaobs
 */
public class Token {
	/**
	 * token id 唯一
	 */
	private String tokenId;
	/**
	 * 用户id
	 */
	private String userId;
	/**
	 * 状态 0启用  1停用
	 */
	private Integer tokenState;
	/**
	 * 创建时间
	 */
	private Long createTime;
	/**
	 * token最后使用时间
	 */
	private Long lastUseTime;
	/**
	 * 类型
	 */
	private Integer tokenType;
	/**
	 * 使用次数
	 */
	private Integer useNumber;

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public Integer getTokenState() {
		return tokenState;
	}

	public void setTokenState(Integer tokenState) {
		this.tokenState = tokenState;
	}

	public Long getCreateTime() {
		return createTime;
	}

	public void setCreateTime(Long createTime) {
		this.createTime = createTime;
	}

	public Long getLastUseTime() {
		return lastUseTime;
	}

	public void setLastUseTime(Long lastUseTime) {
		this.lastUseTime = lastUseTime;
	}

	public Integer getTokenType() {
		return tokenType;
	}

	public void setTokenType(Integer tokenType) {
		this.tokenType = tokenType;
	}

	public Integer getUseNumber() {
		return useNumber;
	}

	public void setUseNumber(Integer useNumber) {
		this.useNumber = useNumber;
	}
}

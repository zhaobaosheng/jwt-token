package com.zdawn.jwt.spi.impl;

import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.zdawn.jwt.spi.Token;
import com.zdawn.jwt.spi.TokenStore;
import com.zdawn.jwt.spi.WebToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * jwt token 缺省实现
 * @author zhaobs
 * jwt header alg=RS256 typ=JWT
 * jwt payload iss=sinosoft exp=到期时间 sub=metering or timekeeping iat=发布时间   jti=tokenId
 */
public class WebTokenImpl implements WebToken {
	private static Logger log = LoggerFactory.getLogger(WebTokenImpl.class);
	/**
	 * token过期时间 单位分钟
	 */
	private int expireTime = 30;
	/**
	 * 支持过期的token转存至历史
	 */
	private boolean tokenHistory = false;
	/**
	 * 计次方式使用次数
	 */
	private int meteringCount = 1;
	/**
	 * 相同身份标识准许分发token次数
	 */
	private int uidTokenCount = 1;
	/**
	 * 私钥
	 */
	private Key privateKey;
	/**
	 * 公钥
	 */
	private Key publicKey;
	/**
	 * token存储接口
	 */
	private TokenStore tokenStore;
	/**
	 * 获取公钥的密码
	 */
	private List<String> securityKeyList;
	//jwt header
	private Map<String,Object> header;
	//base64 public key
	private String verifierKey;
	
	private Map<String,Object> getHeader(){
		if(header==null) {
			header = new HashMap<String, Object>();
			header.put("alg","RS256");
			header.put("typ", "JWT");
		}
		return header;
	}
	
	private Token createToken(String uid, String type) {
		Token token  = new Token();
		token.setTokenId(UUID.randomUUID().toString());
		token.setUserId(uid);
		long currentTime = System.currentTimeMillis();
		token.setCreateTime(currentTime);
		token.setLastUseTime(currentTime);
		token.setTokenState(0);
		int tokenType = 2;//timekeeping
		if("metering".equals(type)) tokenType = 1;
		token.setTokenType(tokenType);
		token.setUseNumber(0);
		return token;
	}
	
	private Token getEarliestToken(List<Token> list) {
		if(list.size()==1) return list.get(0);
		long lastTime = System.currentTimeMillis()+1000L;
		Token temp = null;
		for (Token token : list) {
			if(token.getTokenState()==1) return token;
			if(token.getLastUseTime()<lastTime) {
				lastTime = token.getLastUseTime();
				temp = token;
			}
		}
		return temp;
	}
	
	public String getJwtToken(String uid, String type) throws Exception {
		String jwt = null;
		try {
			//query by uid
			List<Token> list = tokenStore.queryTokenByUserId(uid);
			if(list!=null && uidTokenCount<=list.size()) {
				Token earlyToken = getEarliestToken(list);
				if(tokenHistory) {
					tokenStore.moveHistoryToken(earlyToken.getTokenId());
				}else {
					tokenStore.delTokenById(earlyToken.getTokenId());
				}
			}
			//create token
			Token token = createToken(uid, type);
			tokenStore.saveToken(token);
			//convert jwt
			Map<String, Object> claims = new HashMap<String, Object>();
			claims.put("iss", "sinosoft");
//			claims.put("exp", new Date(token.getLastUseTime()));
			claims.put("sub", type);
//			claims.put("iat", new Date(token.getCreateTime()));
			claims.put("jti", token.getTokenId());
			jwt = Jwts.builder().setHeader(getHeader()).setClaims(claims).signWith(privateKey, SignatureAlgorithm.RS256).compact();
		} catch (Exception e) {
			throw e;
		}
		return jwt;
	}

	public String verifyJwtToken(String jwtToken) throws Exception {
		String uid = null;
		try {
			//verify sign
			Jws<Claims> claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwtToken);
			String tokenId = claims.getBody().getId();
			//load token
			Token token = tokenStore.queryTokenById(tokenId);
			if(token==null) throw new Exception("token not exist");
			uid = token.getUserId();
			//verify expire
			if(token.getTokenState()==1) throw new Exception("token expire");
			long currentTime = System.currentTimeMillis();
			boolean expire = false;
			if(1==token.getTokenType()) {//metering
				if(currentTime-token.getLastUseTime()>expireTime*60000) {
					token.setTokenState(1);
					expire = true;
				}
				if(!expire) {
					if(meteringCount<=token.getUseNumber()) {
						expire = true;
					}
				}
			}else {//timekeeping
				if(currentTime-token.getLastUseTime()>expireTime*60000) {
					token.setTokenState(1);
					expire = true;
				}
			}
			if(expire) {//过期
				if(tokenHistory) {
					tokenStore.updateToken(token);
					tokenStore.moveHistoryToken(token.getTokenId());
				}else {
					tokenStore.delTokenById(token.getTokenId());
				}
				throw new Exception("token expire");
			}else {//没过期
				token.setLastUseTime(currentTime);
				if(1==token.getTokenType()) token.setUseNumber(token.getUseNumber()+1);
				tokenStore.updateToken(token);
			}
		} catch (Exception e) {
			throw e;
		}
		return uid;
	}

	public void clearExpireToken() {
		try {
			if(tokenHistory) {
				tokenStore.moveHistoryTokenByOverTime(expireTime);
			}else {
				tokenStore.clearTokenByOverTime(expireTime);
			}
		} catch (Exception e) {
			log.error("clearExpireToken==>",e);
		}
	}

	@Override
	public Map<String, String> getTokenConfig() {
		Map<String,String> config = new HashMap<>();
		if(verifierKey==null) {
			verifierKey = Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
		}
		config.put("alg","RS256");
		config.put("pubKey",verifierKey);
		config.put("expireTime",expireTime+"");
		config.put("meteringCount",meteringCount+"");
		config.put("tokenHistory",tokenHistory+"");
		return config;
	}
	
	public void setTokenConfig(Map<String, String> config) {
		try {
			//expireTime
			String temp = config.get("expireTime");
			if(temp!=null && !"".equals(temp)) {
				expireTime = Integer.parseInt(temp);
				log.info("set expireTime "+temp);
			}
			//meteringCount
			temp = config.get("meteringCount");
			if(temp!=null && !"".equals(temp)) {
				meteringCount = Integer.parseInt(temp);
				log.info("set meteringCount "+temp);
			}
			//tokenHistory
			temp = config.get("tokenHistory");
			if(temp!=null && !"".equals(temp)) {
				tokenHistory = Boolean.parseBoolean(temp);
				log.info("set tokenHistory "+temp);
			}
			//pubKey
			temp = config.get("pubKey");
			if(temp!=null && !"".equals(temp)) {
				X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(temp.getBytes()));
			    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			    publicKey = keyFactory.generatePublic(pubX509);
			}
			//priKey
			temp = config.get("priKey");
			if(temp!=null && !"".equals(temp)) {
				 PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(temp.getBytes()));
		         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		         privateKey = keyFactory.generatePrivate(keySpec);
			}
		}catch (Exception e) {
			log.error("setTokenConfig",e);
		}
	}

	@Override
	public boolean validateSecurityKeyForPublicKey(String securityKey) {
		if(securityKeyList==null) return false;
		return securityKeyList.contains(securityKey);
	}

	@Override
	public void validateTokenConfig() {
		if(uidTokenCount>10) log.warn("相同身份标识准许分发token个数不推荐大于10");
		if(meteringCount>3) log.warn("计次方式使用次数不推荐大于3");
		tokenStore.validateTokenConfig(this);
	}
	
	@Override
	public void delJwtToken(String jwtToken) throws Exception {
		//解析tokenid
		Jws<Claims> claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwtToken);
		String tokenId = claims.getBody().getId();
		if(tokenId!=null) tokenStore.delTokenById(tokenId);
	}

	@Override
	public void delJwtTokenByUid(String uid) throws Exception {
		List<Token> list = tokenStore.queryTokenByUserId(uid);
		if(list==null) return ;
		for (Token token : list) {
			tokenStore.delTokenById(token.getTokenId());
		}
	}
	
	/******************gen auto*****************/
	
	public void setExpireTime(int expireTime) {
		this.expireTime = expireTime;
	}

	public void setTokenHistory(boolean tokenHistory) {
		this.tokenHistory = tokenHistory;
	}

	public void setMeteringCount(int meteringCount) {
		this.meteringCount = meteringCount;
	}

	public void setUidTokenCount(int uidTokenCount) {
		this.uidTokenCount = uidTokenCount;
	}

	public void setPrivateKey(Key privateKey) {
		this.privateKey = privateKey;
	}

	public void setPublicKey(Key publicKey) {
		this.publicKey = publicKey;
	}

	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	public void setSecurityKeyList(List<String> securityKeyList) {
		this.securityKeyList = securityKeyList;
	}
}

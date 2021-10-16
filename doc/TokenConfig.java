package com.test.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Arrays;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;

import com.zdawn.jwt.spi.TokenStore;
import com.zdawn.jwt.spi.WebToken;
import com.zdawn.jwt.spi.impl.RedisTokenStore;
import com.zdawn.jwt.spi.impl.WebTokenImpl;
import com.zdawn.jwt.web.TokenVerifierFilter;
import com.zdawn.jwt.web.WebTokenConfigServlet;

@Configuration
public class TokenConfig {
	private static Logger log = LoggerFactory.getLogger(TokenConfig.class);
	/**
	 * 证书路径可在配置文件配置,文件为.jks文件
	 * **/
	@Value("${jwt.token.resource.keyStoreName}")
	private String keyStoreName;
	/**
	 * 证书密码  在配置文件配置(生成.jks文件时设置的密码)
	 * **/
	@Value("${jwt.token.resource.password}")
	private String password;
	/**
	 * 证书别名 在配置文件配置(生成.jks文件时设置的别名)
	 * **/
	@Value("${jwt.token.resource.key-pair-alias}")
	private String keyPairAlias;
	
	@Bean
	public WebToken webToken(){
		InputStream is = null;
		//jwt token 缺省实现
		WebTokenImpl token = new WebTokenImpl();
		try {
			//token存储接口
			token.setTokenStore(tokenStore());
			//读取证书
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			is =  TokenConfig.class.getClassLoader().getResourceAsStream(keyStoreName);
			keyStore.load(is, password.toCharArray());
			//设置私钥
			token.setPrivateKey(keyStore.getKey(keyPairAlias, password.toCharArray()));
			//设置公钥
			token.setPublicKey(keyStore.getCertificate(keyPairAlias).getPublicKey());
			//设置获取公钥的密码
			token.setSecurityKeyList(Arrays.asList("123456"));
			//token过期时间 单位分钟 默认30分钟
			//token.setExpireTime(1);
			//支持过期的token转存至历史 默认false,不转存历史
			//token.setTokenHistory(true);
			//计次方式使用次数,默认为1
			//token.setMeteringCount(2);
			//相同身份标识准许分发token次数默认为1
			//token.setUidTokenCount(2);
		} catch (Exception e) {
			e.printStackTrace();
		}finally {
			try {
				if(is!=null) is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return token;
	}
	@Bean
	public TokenStore tokenStore(){
		RedisTokenStore tokenStore = new RedisTokenStore();
		InputStream is = null;
		try {
			is = TokenConfig.class.getClassLoader().getResourceAsStream("redisson-config.yml");
			Config config = Config.fromYAML(is);
			RedissonClient redissonClient = Redisson.create(config);
			tokenStore.setRedissonClient(redissonClient);
		} catch (Exception e) {
			log.error("tokenStore",e);
		}finally {
			try {
				if(is!=null) is.close();
			} catch (IOException e) {}
		}
		return tokenStore;
	}
	
	@Bean
    public FilterRegistrationBean<TokenVerifierFilter> tokenVerifierFilterRegistrationBean(){
        FilterRegistrationBean<TokenVerifierFilter> bean = new FilterRegistrationBean<>();
        TokenVerifierFilter filter = new TokenVerifierFilter();
        //设置filter不验证url列表
        filter.addExceptUrl("/WebToken/getTokenConfig.do","/getToken");
        //jwt接口
        filter.setWebToken(webToken());
        //获取token config的密码
        filter.setSecurityKey("123456");
        bean.setFilter(filter);
        bean.addUrlPatterns("/*");
        return bean;
    }
	
	@Bean
    public ServletRegistrationBean<WebTokenConfigServlet> webTokenConfigServletRegistrationBean(){
		WebTokenConfigServlet configServlet = new WebTokenConfigServlet();
		configServlet.setWebToken(webToken());
		ServletRegistrationBean<WebTokenConfigServlet> bean = new ServletRegistrationBean<>();
		bean.setServlet(configServlet);
		bean.addUrlMappings("/WebToken/getTokenConfig.do");
        return bean;
    }
	
	@Scheduled(cron="0/30 * * * * ?")
	public void clearExpireToken(){
		//定时清理过期token,在webToken()方法可设置转存历史表,默认直接清除
		webToken().clearExpireToken();
	}
}

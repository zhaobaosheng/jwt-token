package com.test.config;

import java.io.IOException;
import java.io.InputStream;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.zdawn.jwt.spi.TokenStore;
import com.zdawn.jwt.spi.impl.RedisTokenStore;
import com.zdawn.jwt.web.TokenVerifierFilter;

@Configuration
public class TokenFilterConfig {
	private static Logger log = LoggerFactory.getLogger(TokenFilterConfig.class);
	
	@Bean
	public FilterRegistrationBean<TokenVerifierFilter> filterRegistrationBean(){
        FilterRegistrationBean<TokenVerifierFilter> bean = new FilterRegistrationBean<>();
        TokenVerifierFilter filter = new TokenVerifierFilter();
        //设置filter不验证url列表
        filter.addExceptUrl("/jwtTokenTest/getJwtToken");
        //设置获取验证token所需配置的url
        filter.setVerifyTokenConfigUrl("http://localhost:9001/pms/WebToken/getTokenConfig.do");
        //token存储接口
        filter.setTokenStore(tokenStore());
        //获取token config的密码
        filter.setSecurityKey("123456");
        bean.setFilter(filter);
        bean.addUrlPatterns("/*");
        return bean;
    }
	
	@Bean
	public TokenStore tokenStore(){
		RedisTokenStore tokenStore = new RedisTokenStore();
		InputStream is = null;
		try {
			is = TokenFilterConfig.class.getClassLoader().getResourceAsStream("redisson-config.yml");
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
}

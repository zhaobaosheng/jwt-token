package com.zdawn.jwt.web;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zdawn.jwt.spi.WebToken;

/**
 * 提供获取公钥参数的web方法
 * @author zhaobs
 */
public class WebTokenConfigServlet extends HttpServlet {
	private static final long serialVersionUID = 2482303976275355486L;

	private static Logger log = LoggerFactory.getLogger(WebTokenConfigServlet.class);
	
	private WebToken webToken;
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		doPost(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String json = "{}";
		req.setCharacterEncoding("UTF-8");
		String key = req.getHeader("security-key");
		Map<String,String> result = null;
		if(key==null) {
			result = new HashMap<String,String>();
			result.put("result","false");
			result.put("desc","require security-key in header");
		}else {
			if(webToken.validateSecurityKeyForPublicKey(key)) {
				result = webToken.getTokenConfig();
				result.put("result","true");
			}else {
				result = new HashMap<String,String>();
				result.put("result","false");
				result.put("desc","security-key not pass");
			}
		}
		try {
			ObjectMapper mapper = new ObjectMapper();
			json = mapper.writeValueAsString(result);
		} catch (JsonProcessingException e) {
			log.error("getTokenKey==>",e);
		}
		//to response
		resp.setContentType("text/json; charset=utf-8");
		resp.setHeader("Cache-Control", "no-cache");
		OutputStream outputStream = resp.getOutputStream();
		byte[] dataByteArr = json.getBytes("UTF-8");
		outputStream.write(dataByteArr);
		outputStream.flush();
	}

	public void setWebToken(WebToken webToken) {
		this.webToken = webToken;
	}
}

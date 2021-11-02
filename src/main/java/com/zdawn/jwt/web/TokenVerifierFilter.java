package com.zdawn.jwt.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zdawn.jwt.spi.TokenStore;
import com.zdawn.jwt.spi.WebToken;
import com.zdawn.jwt.spi.impl.WebTokenImpl;

/**
 * 验证jwt token过滤器
 * @author zhaobs
 */
public class TokenVerifierFilter implements Filter {
	private static Logger log = LoggerFactory.getLogger(TokenVerifierFilter.class);
	/**
	 * 不验证url列表
	 */
	private List<String> exceptUrlList;
	/**
	 * 获取验证token所需配置的url
	 */
	private String verifyTokenConfigUrl;
	/**
	 * jwt接口
	 */
	private WebToken webToken;
	/**
	 * 获取token config的密码
	 */
	private String securityKey;
	/**
	 * 存放jwt http header key
	 */
	private String jwtHttpHeaderKey = "Authorization";
	/**
	 * 最后拉取token config 时间
	 */
	private boolean pullTokenConfig = false;
	/**
	 * 是否检查uid
	 */
	private boolean checkUid = false;
	/**
	 * uid解码接口
	 */
	private UidDecoder decoder = new IgnoreUidDecoder();
	/**
	 * 客户端uid http header key
	 */
	private String uidHttpHeaderKey = "uid";
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if(!pullTokenConfig) {
			pullTokenConfig();
		}
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		try {
			//过滤URL
			if(exceptURL(req.getRequestURI(), req.getContextPath(), exceptUrlList)){
				chain.doFilter(request, response);
			}else{
				//获取请求传来的参数
				try {
					String token = req.getHeader(jwtHttpHeaderKey);
					if(token ==null || "".equals(token)){
						//find query string
						token = parseValue(req.getQueryString(), jwtHttpHeaderKey);
					}
					if(token ==null || "".equals(token)) throw new Exception("jwt token为空");
					String uid = webToken.verifyJwtToken(token);
					if(checkUid) {
						String inputUid = req.getHeader(uidHttpHeaderKey);
						if(inputUid ==null || "".equals(inputUid)) {
							//find from query string
							inputUid = parseValue(req.getQueryString(), uidHttpHeaderKey);
						}
						String passUid = decoder.decodeUid(inputUid);
						if(passUid==null || !uid.equals(passUid)) throw new Exception("check uid failure");
					}
					chain.doFilter(request, response);
				} catch (Exception e) {
					res.setContentType("application/json;charset=utf-8");
					OutputStream outputStream = res.getOutputStream();
	        		String data = getResultInfo(false,e.getMessage());
	        		byte[] dataByteArr = data.getBytes("UTF-8");
	        		outputStream.write(dataByteArr);
	        		outputStream.flush();
	        		outputStream.close();
				}
			}
		} catch (Exception e) {
			log.error("doFilter",e);
		}
	}

	@Override
	public void destroy() {
	}

	public void setExceptUrlList(List<String> exceptUrlList) {
		this.exceptUrlList = exceptUrlList;
	}

	public void addExceptUrl(String... url) {
		if(exceptUrlList==null) {
			exceptUrlList = new ArrayList<String>();
		}
		for (String one : url) {
			exceptUrlList.add(one);
		}
	}

	public void setVerifyTokenConfigUrl(String verifyTokenConfigUrl) {
		this.verifyTokenConfigUrl = verifyTokenConfigUrl;
	}
	
	public void setTokenStore(TokenStore tokenStore) {
		if(webToken==null) webToken = new WebTokenImpl();
		if(webToken instanceof WebTokenImpl) {
			WebTokenImpl impl = (WebTokenImpl)webToken;
			impl.setTokenStore(tokenStore);
		}
	}

	public void setWebToken(WebToken webToken) {
		this.webToken = webToken;
	}
	
    public void setSecurityKey(String securityKey) {
		this.securityKey = securityKey;
	}

	private boolean exceptURL(String currentURL, String contextPath, List<String> exceptList) {
        if (exceptList == null || exceptList.size() == 0) {
            return false;
        }
        currentURL = currentURL.substring(contextPath.length(), currentURL.length());
        for (String temp : exceptList) {
            int index = temp.indexOf("*");
            if (index > 0) {
                String sub = temp.substring(0, index);
                if (currentURL.startsWith(sub) && currentURL.length() > sub.length()) {
                    return true;
                }
            } else {
                if (currentURL.equals(temp)) {
                    return true;
                }
            }
        }
        return false;
    }
    
	private String getResultInfo(boolean result,String message) {
		Map<String,Object> map = new HashMap<String,Object>();
		map.put("result",result);
		map.put("desc",message);
		//to json
		String json = null;
		try {
			ObjectMapper mapper = new ObjectMapper();
			json = mapper.writeValueAsString(map);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		return json;
	}
	
	private synchronized void pullTokenConfig() {
		if(pullTokenConfig) return ;
		if(verifyTokenConfigUrl==null) {
			pullTokenConfig = true;
			return;
		}
		try {
			String jsonString = getVerifyTokenConfig(verifyTokenConfigUrl, 10 * 1000, 10 * 1000);
			Map<String,String> config = parseTokenConfig(jsonString);
			webToken.setTokenConfig(config);
			webToken.validateTokenConfig();
			pullTokenConfig = true;
		} catch (Exception e) {
			log.error(verifyTokenConfigUrl);
			log.error("pullTokenConfig",e);
		}
	}
	
	private String getVerifyTokenConfig(String serviceUrl,int connectTimeout,int readTimeout) throws Exception{
		HttpURLConnection connection = null;
		String charset = "UTF-8";
		String result = null;
		try {
			// Create connection
			byte[] data = "get token config".getBytes();
			URL url = new URL(serviceUrl);
			URLConnection temp = url.openConnection();
			connection = (HttpURLConnection)temp;
			connection.setConnectTimeout(connectTimeout);
			connection.setReadTimeout(readTimeout);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type","application/x-www-form-urlencoded; charset="+charset);
			connection.setRequestProperty("Accept-Charset",charset);
			connection.setRequestProperty("Content-Length",data.length+"");
			connection.setRequestProperty("Accept","text/html,application/json,application/xml");
			connection.setRequestProperty("security-key",securityKey);
			connection.setUseCaches(false);
			connection.setDoInput(true);
			connection.setDoOutput(true);
			// Send request
			OutputStream os = connection.getOutputStream();
			os.write(data);
			os.flush();

			// Get Response
			int responseCode = connection.getResponseCode();
			if(responseCode==HttpURLConnection.HTTP_OK){
				InputStream is = connection.getInputStream();
				BufferedReader rd = new BufferedReader(new InputStreamReader(is,charset));
				String line=null;
				StringBuilder sb = new StringBuilder();
				while ((line = rd.readLine()) != null) {
					sb.append(line);
				}
				rd.close();
				result = sb.toString();
			}else{
				InputStream is= connection.getErrorStream();
				BufferedReader rd = new BufferedReader(new InputStreamReader(is,charset));
				String line=null;
				StringBuilder sb = new StringBuilder();
				while ((line = rd.readLine()) != null) {
					sb.append(line);
				}
				rd.close();
				throw new Exception(sb.toString());
			}
		} catch (Exception e) {
			throw e;
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
		return result;
	}
	private Map<String,String> parseTokenConfig(String jsonString) throws Exception{
		ObjectMapper mapper = new ObjectMapper();
		Map<String,String> data = new HashMap<String,String>();
		try {
			JsonNode rootNode = mapper.readValue(jsonString,JsonNode.class);
			Iterator<String> it = rootNode.fieldNames();
			while (it.hasNext()) {
				String name = it.next();
				JsonNode one = rootNode.path(name);
				if(one.isValueNode()){
					data.put(name, one.asText());
				}
			}
		} catch (Exception e) {
			throw e;
		}
		return data;
	}
	
	private String parseValue(String queryString,String key) {
		if(queryString==null || queryString.equals("")) return null;
		int stringStart = 0;
        String attrName = null;
        for (int i = 0; i < queryString.length(); ++i) {
            char c = queryString.charAt(i);
            if (c == '=' && attrName == null) {
                attrName = queryString.substring(stringStart, i);
                stringStart = i + 1;
            } else if (c == '&') {
                if (attrName != null) {
                	String value = queryString.substring(stringStart, i);
                	if(key.equals(attrName)) return value;
                } else {
                	String onlyKey = queryString.substring(stringStart, i);
                	if(key.equals(onlyKey)) return null;
                }
                stringStart = i + 1;
                attrName = null;
            }
        }
        if (attrName != null) {
        	String value = queryString.substring(stringStart, queryString.length());
        	if(key.equals(attrName)) return value;
        } else if (queryString.length() != stringStart) {
        	String onlyKey =  queryString.substring(stringStart, queryString.length());
        	if(key.equals(onlyKey)) return null;
        }
        return null;
	}
	/**
	 * 设置jwt http header key or url queryString parameter key  默认Authorization
	 */
	public void setJwtHttpHeaderKey(String jwtHttpHeaderKey) {
		this.jwtHttpHeaderKey = jwtHttpHeaderKey;
	}
	/**
	 * 是否强制检查 http header uid 与token中一致
	 */
	public void setCheckUid(boolean checkUid) {
		this.checkUid = checkUid;
	}
	/**
	 *  http header中提交uid key 默认为uid
	 */
	public void setUidHttpHeaderKey(String uidHttpHeaderKey) {
		this.uidHttpHeaderKey = uidHttpHeaderKey;
	}
	/**
	 * 设置 http header中解码uid实现类 默认不做处理
	 */
	public void setDecoder(UidDecoder decoder) {
		this.decoder = decoder;
	}
	
}

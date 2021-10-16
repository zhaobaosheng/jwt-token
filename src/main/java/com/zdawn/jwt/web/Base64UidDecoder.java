package com.zdawn.jwt.web;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class Base64UidDecoder implements UidDecoder {

	@Override
	public String decodeUid(String value) {
		if(value==null || "".equals(value)) return null;
		try {
			byte[] data = Base64.getMimeDecoder().decode(value.getBytes("UTF-8"));
			value = new String(data,"UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		return value;
	}
	
	public static void main(String[] arg) {
		Base64UidDecoder d = new Base64UidDecoder();
		System.out.println(d.decodeUid("MXFheg=="));
	}
}

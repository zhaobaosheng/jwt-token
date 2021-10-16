package com.zdawn.jwt.web;

public interface UidDecoder {
	default public String decodeUid(String value) {
		return value;
	}
}

package com.eazybytes.eazystore.constants;

public class ApplicationConstants {

    private ApplicationConstants() {
        throw new AssertionError("Utility class cannot be instantiated.");

    }
    public static final String JWT_TOKEN_HEADER = "Authorization";
    public  static final String JWT_SECRET_KEY = "JWT_SECRET";
    public static final String JWT_SECRET_DEFAULT_VALUE="xgEQeXHuPq8VdbyYFNKANdud053YUn4A";
}

package com.eazybytes.eazystore.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@Configuration
public class CaffeineCacheConfig {
   @Bean
    public CacheManager caffeineCacheManager() {
       CaffeineCache productCache= new CaffeineCache("products",
               Caffeine.newBuilder()
                       .expireAfterWrite(30, TimeUnit.SECONDS)
                       .maximumSize(1000)
                       .build());
       CaffeineCache customerCache= new CaffeineCache("roles",
               Caffeine.newBuilder()
                       .expireAfterWrite(1, TimeUnit.DAYS)
                       .maximumSize(1)
                       .build());

       SimpleCacheManager simpleCacheManager = new SimpleCacheManager();
       simpleCacheManager.setCaches(Arrays.asList(productCache, customerCache));
       return simpleCacheManager;


    }
}

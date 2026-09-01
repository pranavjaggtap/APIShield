package com.apishield;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.test.StepVerifier;

/**
 * Verifies a live SET/GET round trip against Redis. Skipped by default so {@code ./mvnw test}
 * never requires a running Redis instance; run explicitly with
 * {@code REDIS_INTEGRATION_TEST=true ./mvnw test} against a reachable Redis.
 */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "REDIS_INTEGRATION_TEST", matches = "true")
class RedisConnectivityTest {

    private static final String KEY = "apishield:connectivity-test";

    @Autowired
    private ReactiveStringRedisTemplate redisTemplate;

    @Test
    void canSetAndGetFromRedis() {
        StepVerifier.create(
                        redisTemplate.opsForValue().set(KEY, "ok")
                                .then(redisTemplate.opsForValue().get(KEY)))
                .expectNext("ok")
                .verifyComplete();

        StepVerifier.create(redisTemplate.delete(KEY))
                .expectNextCount(1)
                .verifyComplete();
    }

}

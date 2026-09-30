package com.apishield.userservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserController {

    @GetMapping("/users/{id}")
    public Map<String, Object> getUser(@PathVariable Long id) {
        return Map.of(
                "id", id,
                "name", "John Doe",
                "email", "john@example.com",
                "source", "user-service"
        );
    }

}

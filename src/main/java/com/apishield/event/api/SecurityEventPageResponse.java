package com.apishield.event.api;

import java.util.List;

/**
 * One page of security events, newest first. {@code page} is zero-based.
 */
public record SecurityEventPageResponse(
        List<SecurityEventResponse> content,
        int page,
        int size,
        long totalElements,
        long totalPages
) {

    static SecurityEventPageResponse of(List<SecurityEventResponse> content, int page, int size, long totalElements) {
        long totalPages = (totalElements + size - 1) / size;
        return new SecurityEventPageResponse(content, page, size, totalElements, totalPages);
    }
}

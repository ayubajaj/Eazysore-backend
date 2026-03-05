package com.eazybytes.eazystore.dto;

public record ContactResponseDto(Long ContactId, String name, String email, String mobileNumber, String message, String status) {
}

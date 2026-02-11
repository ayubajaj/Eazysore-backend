package com.eazybytes.eazystore.service;

import com.eazybytes.eazystore.dto.ProfileRequestDto;
import com.eazybytes.eazystore.dto.ProfileResponseDto;
import org.springframework.validation.annotation.Validated;

public interface IProfileService {
    ProfileResponseDto getProfile();
    ProfileResponseDto updateProfile(ProfileRequestDto profileRequestDto);

}

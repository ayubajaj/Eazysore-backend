package com.eazybytes.eazystore.service;

import com.eazybytes.eazystore.dto.ContactRequestDto;
import com.eazybytes.eazystore.dto.ContactResponseDto;
import com.eazybytes.eazystore.dto.ProductDto;

import java.util.List;

public interface IContactService {

    boolean saveContact(ContactRequestDto contactRequestDto);

    void updateMessageStatus(Long contactId, String closedMessage);

    List<ContactResponseDto> getAllOpenMessages();
}

package com.artur.request.model;

import java.util.List;

public record ClientCreateRequest(
        String clientName,
        String secret,
        String redirectUris,
        List<String> grantTypes,
        String scope
) {
}

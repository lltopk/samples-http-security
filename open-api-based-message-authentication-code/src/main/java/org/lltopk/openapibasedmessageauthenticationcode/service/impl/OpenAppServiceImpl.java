package org.lltopk.openapibasedmessageauthenticationcode.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.lltopk.openapibasedmessageauthenticationcode.model.OpenAppPo;
import org.lltopk.openapibasedmessageauthenticationcode.service.IOpenAppService;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class OpenAppServiceImpl implements IOpenAppService {
    @Override
    public OpenAppPo getByAppKey(String appKey) {
        return null;
    }
}

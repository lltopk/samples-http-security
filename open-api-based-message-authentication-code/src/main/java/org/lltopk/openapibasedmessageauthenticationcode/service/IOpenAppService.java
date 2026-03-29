package org.lltopk.openapibasedmessageauthenticationcode.service;

import org.lltopk.openapibasedmessageauthenticationcode.model.OpenAppPo;

public interface IOpenAppService {
    OpenAppPo getByAppKey(String appKey);
}

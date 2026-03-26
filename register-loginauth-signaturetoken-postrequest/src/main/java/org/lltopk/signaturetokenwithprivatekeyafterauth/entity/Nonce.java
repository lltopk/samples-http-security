package org.lltopk.signaturetokenwithprivatekeyafterauth.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Nonce {
    private Long id;
    private String nonce;
    private Long timestamp;
    private LocalDateTime createTime;
}

package org.lltopk.signaturetokenwithprivatekeyafterauth.dao;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.lltopk.httpsecuritycommon.po.UserPo;
import org.lltopk.signaturetokenwithprivatekeyafterauth.entity.Nonce;

@Mapper
public interface UserMapper {
    
    /**
     * Find user by id
     */
    UserPo findById(@Param("id") Long id);
    
    /**
     * Find user by username
     */
    UserPo findByUsername(@Param("username") String username);
    
    /**
     * Find user by email
     */
    UserPo findByEmail(@Param("email") String email);
    
    /**
     * Save new user
     */
    int save(UserPo user);
    
    /**
     * Update user
     */
    int update(UserPo user);
    
    /**
     * Find nonce by value (for replay attack prevention)
     */
    Nonce findNonce(@Param("nonce") String nonce);
    
    /**
     * Save nonce (for replay attack prevention)
     */
    int saveNonce(@Param("nonce") String nonce, @Param("timestamp") Long timestamp);
    
    /**
     * Delete expired nonces
     */
    int deleteExpiredNonces(@Param("expireTime") Long expireTime);
}

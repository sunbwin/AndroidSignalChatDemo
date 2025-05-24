package com.your_app_name.signalchat

import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Path

// 这个数据类用于匹配服务器返回的注册用户公钥结构
// 注意：preKeys 是一个 Map<String, String>，因为其键是 preKeyId (String)
data class UserKeysResponse(
    val userId: String,
    val registrationId: Int, // 新增：从服务器获取的注册ID
    val identityKey: String, // Base64 编码的身份公钥
    val signedPreKey: SignedPreKeyData, // 签名预密钥数据
    val preKeys: Map<String, String> // Map<preKeyId, Base64 编码的公钥>
)

// 签名预密钥的数据结构
data class SignedPreKeyData(
    val keyId: Int,
    val publicKey: String, // Base64 编码的签名预密钥公钥
    val signature: String // Base64 编码的签名
)

interface ApiService {
    // 定义获取用户公钥的 GET 请求
    // @Path("userId") 会将函数参数 userId 替换到 URL 路径中
    @GET("get_keys/{userId}")
    suspend fun getUserKeys(@Path("userId") userId: String): Response<UserKeysResponse>
}

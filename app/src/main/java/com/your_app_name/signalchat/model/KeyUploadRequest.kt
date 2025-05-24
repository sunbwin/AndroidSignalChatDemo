package com.your_app_name.signalchat.model

data class KeyUploadRequest(
    val userId: String,
    val identityKey: String,
    val registrationId: Int,
    val signedPreKeyId: Int,
    val signedPreKeyPublic: String,
    val signedPreKeySignature: String,
    val preKeys: List<PreKeyJson>
)

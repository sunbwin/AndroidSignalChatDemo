package com.your_app_name.signalchat.network

import com.your_app_name.signalchat.model.KeyUploadRequest
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

interface KeyService {
    @POST("/keys/upload")
    suspend fun uploadKeys(@Body request: KeyUploadRequest): Response<Unit>
}

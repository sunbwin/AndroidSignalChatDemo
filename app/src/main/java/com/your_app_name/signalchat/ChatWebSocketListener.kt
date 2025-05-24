package com.your_app_name.signalchat

import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.json.JSONObject
import java.util.Base64

// 定义一个接口，用于将 WebSocket 事件回调给 MainActivity3
interface WebSocketListenerCallback {
    fun onWebSocketConnected()
    // 为普通聊天消息定义的回调
    fun onWebSocketMessage(senderId: String, messageType: Int, encryptedMessageData: String)
    // *** 新增：为认证成功消息定义的回调 ***
    fun onWebSocketAuthenticated(userId: String) // 或者根据需要传递更多认证信息
    fun onWebSocketClosing(code: Int, reason: String)
    fun onWebSocketClosed(code: Int, reason: String)
    fun onWebSocketFailure(t: Throwable, response: Response?)
}

class ChatWebSocketListener(private val callback: WebSocketListenerCallback) : WebSocketListener() {

    private val TAG = "ChatWebSocketListener"

    override fun onOpen(webSocket: WebSocket, response: Response) {
        Log.d(TAG, "WebSocket Opened: ${response.message}")
        callback.onWebSocketConnected()
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onMessage(webSocket: WebSocket, text: String) {
        Log.d(TAG, "Receiving text: $text")
        try {
            val jsonMessage = JSONObject(text)

            // *** 核心修改：根据 JSON 结构判断消息类型 ***
            if (jsonMessage.has("status") && jsonMessage.getString("status") == "authenticated") {
                // 这是服务器发来的认证成功消息
                val userId = jsonMessage.getString("userId")
                callback.onWebSocketAuthenticated(userId)
                Log.d(TAG, "Received authentication success for user: $userId")

            } else if (jsonMessage.has("senderId") && jsonMessage.has("encryptedMessage") && jsonMessage.has("messageType")) {
                // 这是聊天消息
                val senderId = jsonMessage.getString("senderId")
                val encryptedMessageData = jsonMessage.getString("encryptedMessage")
                val messageType = jsonMessage.getInt("messageType")

                callback.onWebSocketMessage(senderId, messageType, encryptedMessageData)
                Log.d(TAG, "Received chat message from $senderId, type: $messageType")

            } else {
                // 未知或不完整的消息类型
                Log.e(TAG, "Received unknown or incomplete message format: $text")
                // 可以选择向回调报告错误或者发送错误消息给服务器
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error parsing incoming WebSocket message: ${e.message}", e)
            // 如果 JSON 格式本身就错误 (e.g. JSONException), 会在这里捕获
        }
    }

    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
        Log.d(TAG, "Receiving bytes: ${bytes.hex()}")
    }

    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        Log.d(TAG, "WebSocket Closing: $code / $reason")
        callback.onWebSocketClosing(code, reason)
        // webSocket.close(1000, null) // 这里通常不需要手动关闭，onClosing 已经是关闭过程的一部分
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        Log.d(TAG, "WebSocket Closed: $code / $reason")
        callback.onWebSocketClosed(code, reason)
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        Log.e(TAG, "WebSocket Failure: ${t.message}", t)
        response?.let {
            Log.e(TAG, "Failure response: ${it.code} / ${it.message}")
        }
        callback.onWebSocketFailure(t, response)
    }
}
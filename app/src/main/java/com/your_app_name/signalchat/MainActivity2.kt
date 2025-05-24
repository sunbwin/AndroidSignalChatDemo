package com.your_app_name.signalchat

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import okhttp3.*
import okio.ByteString
import org.json.JSONObject
import kotlinx.coroutines.*
import kotlin.coroutines.CoroutineContext
import android.widget.Toast // 用于显示提示信息

class MainActivity2 : AppCompatActivity(), CoroutineScope {

    private val TAG = "WebSocketClient"

    private lateinit var editTextUsername: EditText
    private lateinit var editTextRecipient: EditText
    private lateinit var editTextMessage: EditText
    private lateinit var buttonSend: Button
    private lateinit var textViewChat: TextView

    private var webSocket: WebSocket? = null
    private val client = OkHttpClient()

    // 当前用户的用户名
    private var currentUser: String? = null

    // CoroutineScope for managing coroutines
    private lateinit var job: Job
    override val coroutineContext: CoroutineContext
        get() = Dispatchers.Main + job

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 使用了 AppCompatActivity 和传统的 View，确保在 AndroidManifest.xml 或 styles.xml 中使用了 AppCompat 主题
        // 如果您之前遇到了主题问题，请确保已经根据之前的指导解决了。
        setContentView(R.layout.activity_main2)

        job = Job()

        editTextUsername = findViewById(R.id.editTextUsername)
        editTextRecipient = findViewById(R.id.editTextRecipient)
        editTextMessage = findViewById(R.id.editTextMessage)
        buttonSend = findViewById(R.id.buttonSend)
        textViewChat = findViewById(R.id.textViewChat)

        // **重要：替换为你电脑的热点IP地址**
        val serverIp = "192.168.1.196" // 例如 "192.168.43.100"
        val serverUrl = "ws://$serverIp:8766"

        // 在这里建立 WebSocket 连接，但先不注册用户
        // 用户点击发送消息时，如果未注册，则先尝试注册
        connectWebSocket(serverUrl)

        buttonSend.setOnClickListener {
            val username = editTextUsername.text.toString().trim()
            val recipient = editTextRecipient.text.toString().trim()
            val message = editTextMessage.text.toString().trim()

            if (currentUser == null) {
                // 用户未注册，先尝试注册
                if (username.isNotEmpty()) {
                    registerUser(username)
                } else {
                    showToast("Please enter your username first.")
                }
            } else {
                // 用户已注册，发送聊天消息
                if (recipient.isNotEmpty() && message.isNotEmpty()) {
                    sendChatMessage(recipient, message)
                    editTextMessage.text.clear() // 清空输入框
                } else {
                    showToast("Please enter recipient and message.")
                }
            }
        }
    }

    private fun connectWebSocket(url: String) {
        val request = Request.Builder().url(url).build()
        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                super.onOpen(webSocket, response)
                Log.d(TAG, "WebSocket opened: ${response.message}")
                // 连接成功，UI上显示提示，但此时用户还未注册
                runOnUiThread {
                    textViewChat.append("Status: Connected to server.\n")
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                super.onMessage(webSocket, text)
                Log.d(TAG, "Receiving: $text")
                try {
                    val jsonObject = JSONObject(text)
                    when (jsonObject.optString("type")) {
                        "registration_success" -> {
                            // 注册成功
                            currentUser = jsonObject.optString("username")
                            runOnUiThread {
                                textViewChat.append("Status: Registered as '${currentUser}'.\n")
                                showToast("Registration successful!")
                                // 注册成功后，禁用用户名输入框和发送按钮，直到输入接收者
                                editTextUsername.isEnabled = false
                                 buttonSend.isEnabled = true // 等待输入接收者用户名再启用发送
                            }
                        }
                        "error" -> {
                            // 注册失败或收到其他错误
                            val errorMessage = jsonObject.optString("text", "Unknown error")
                            runOnUiThread {
                                textViewChat.append("Error: ${errorMessage}\n")
                                showToast("Error: ${errorMessage}")
                                // 注册失败，可能需要重新输入用户名或处理
                                currentUser = null // 重置用户状态
                                editTextUsername.isEnabled = true // 重新启用用户名输入
                                buttonSend.isEnabled = true // 重新启用发送按钮
                            }
                        }
                        "status" -> {
                            // 收到状态消息 (例如用户上线/下线)
                            val statusMessage = jsonObject.optString("text", "Unknown status")
                            runOnUiThread {
                                textViewChat.append("Status: ${statusMessage}\n")
                            }
                        }
                        "chat" -> {
                            // 收到聊天消息
                            val sender = jsonObject.optString("sender")
                            val recipient = jsonObject.optString("recipient")
                            val chatText = jsonObject.optString("text")

                            runOnUiThread {
                                // 根据发送者是否是当前用户来区分显示左右
                                if (sender == currentUser) {
                                    // 我发送的消息，在右侧显示 (这里通过前缀和换行简单模拟，实际需要RecyclerView和不同ViewHolder)
                                    textViewChat.append("You: ${chatText}\n")
                                } else {
                                    // 收到其他人的消息，在左侧显示 (这里通过前缀简单模拟)
                                    textViewChat.append("${sender}: ${chatText}\n")
                                }
                                // 滚动到底部（ScrollView）
                                (textViewChat.parent as? ScrollView)?.fullScroll(TextView.FOCUS_DOWN)
                            }
                        }
                        else -> {
                            // 未知消息类型
                            runOnUiThread {
                                textViewChat.append("Status: Received unknown message type.\n")
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error parsing message: $text", e)
                    runOnUiThread {
                        textViewChat.append("Status: Error processing message: ${e.message}\n")
                    }
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                super.onMessage(webSocket, bytes)
                Log.d(TAG, "Receiving bytes: ${bytes.hex()}")
                // 对于文本聊天应用，通常只处理文本消息
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                super.onClosing(webSocket, code, reason)
                Log.d(TAG, "Closing: $code / $reason")
                runOnUiThread {
                    textViewChat.append("Status: Connection closing: $code / $reason\n")
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                super.onFailure(webSocket, t, response)
                Log.e(TAG, "Error: " + t.message, t)
                runOnUiThread {
                    textViewChat.append("Status: Connection error: ${t.message}\n")
                    showToast("Connection error: ${t.message}")
                    currentUser = null // 连接失败，重置用户状态
                    editTextUsername.isEnabled = true
                    buttonSend.isEnabled = true
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                super.onClosed(webSocket, code, reason)
                Log.d(TAG, "Closed: $code / $reason")
                runOnUiThread {
                    textViewChat.append("Status: Disconnected: $code / $reason\n")
                    showToast("Disconnected.")
                    currentUser = null // 连接关闭，重置用户状态
                    editTextUsername.isEnabled = true
                    buttonSend.isEnabled = true
                }
            }
        })
    }

    private fun registerUser(username: String) {
        if (webSocket != null) {
            val registrationMessage = JSONObject().apply {
                put("type", "register")
                put("username", username)
            }.toString()
            webSocket?.send(registrationMessage)
            runOnUiThread {
                textViewChat.append("Status: Attempting to register as '${username}'...\n")
                buttonSend.isEnabled = false // 注册中，暂时禁用发送
            }
        } else {
            showToast("WebSocket connection not established.")
            runOnUiThread {
                textViewChat.append("Status: WebSocket connection not established.\n")
            }
        }
    }


    private fun sendChatMessage(recipient: String, message: String) {
        if (webSocket != null && currentUser != null) {
            val chatMessage = JSONObject().apply {
                put("type", "chat")
                put("sender", currentUser) // 发送者是当前用户
                put("recipient", recipient) // 接收者是输入的用户名
                put("text", message)
            }.toString()
            webSocket?.send(chatMessage)
            // 消息的显示在接收到服务器回传的消息时处理 (上面 onMessage 中的 sender == currentUser 逻辑)
            // 这样可以确保消息成功到达服务器并被转发后才显示在右侧
        } else {
            showToast("Not connected or registered.")
            runOnUiThread {
                textViewChat.append("Status: Not connected or registered.\n")
            }
        }
    }

    private fun showToast(message: String) {
        runOnUiThread {
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
        }
    }


    override fun onDestroy() {
        super.onDestroy()
        webSocket?.close(1000, "App closing")
        client.dispatcher.executorService.shutdown()
        job.cancel() // Cancel coroutine job
    }
}
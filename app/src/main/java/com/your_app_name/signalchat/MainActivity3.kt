package com.your_app_name.signalchat

import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import org.json.JSONObject
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemoryIdentityKeyStore
import org.signal.libsignal.protocol.state.impl.InMemoryPreKeyStore
import org.signal.libsignal.protocol.state.impl.InMemorySignedPreKeyStore
import org.signal.libsignal.protocol.ecc.Curve
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64
import java.security.SecureRandom
import androidx.lifecycle.lifecycleScope
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage // 导入 PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage // 导入 SignalMessage
// 如果你也需要处理明文消息或 SenderKey 消息，可能还需要：
import org.signal.libsignal.protocol.message.PlaintextContent
import org.signal.libsignal.protocol.message.SenderKeyMessage
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.state.impl.InMemorySessionStore
import org.signal.libsignal.protocol.state.impl.InMemoryKyberPreKeyStore

import java.security.MessageDigest
import java.util.Arrays

class MainActivity3 : AppCompatActivity(), WebSocketListenerCallback { // 实现 WebSocketListenerCallback

    private val TAG = "SignalChatApp"
    private val SERVER_BASE_URL = "http://192.168.1.196:5000" // 确保这是你的服务器 IP
    // WebSocket URL, 注意是 ws:// 或 wss://
    private val WEBSOCKET_URL = "ws://192.168.1.196:8766/ws"

    private lateinit var etUserId: EditText
    private lateinit var btnRegister: Button
    private lateinit var etRecipientId: EditText
    private lateinit var btnFetchKeys: Button
    private lateinit var etMessage: EditText
    private lateinit var btnSendMessage: Button
    private lateinit var etReceivedMessages: EditText // 新增：显示接收到的消息

    private lateinit var identityKeyPair: IdentityKeyPair
    private var registrationId: Int = 0
    private lateinit var identityKeyStore: InMemoryIdentityKeyStore
    private val preKeyStore = InMemoryPreKeyStore()
    private val signedPreKeyStore = InMemorySignedPreKeyStore()
    private val secureRandom = SecureRandom()
    private val sessionStore = InMemorySessionStore()
    private val kyberPreKeyStore = InMemoryKyberPreKeyStore()

    private lateinit var apiService: ApiService

    private val sessionCiphers: MutableMap<String, SessionCipher> = mutableMapOf()

    // WebSocket 客户端相关
    private val okHttpClient = OkHttpClient()
    private var webSocket: WebSocket? = null
    private lateinit var chatWebSocketListener: ChatWebSocketListener

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main3)

        etUserId = findViewById(R.id.etUserId)
        btnRegister = findViewById(R.id.btnRegister)
        etRecipientId = findViewById(R.id.etRecipientId)
        btnFetchKeys = findViewById(R.id.btnFetchKeys)
        etMessage = findViewById(R.id.etMessage)
        btnSendMessage = findViewById(R.id.btnSendMessage)
        etReceivedMessages = findViewById(R.id.etReceivedMessages) // 初始化

        val ecKeyPair = Curve.generateKeyPair()
        identityKeyPair = IdentityKeyPair(
            IdentityKey(ecKeyPair.publicKey.serialize()),
            ECPrivateKey(ecKeyPair.privateKey.serialize())
        )
        registrationId = secureRandom.nextInt(16380) + 1

        identityKeyStore = InMemoryIdentityKeyStore(identityKeyPair, registrationId)

        val retrofit = Retrofit.Builder()
            .baseUrl(SERVER_BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
        apiService = retrofit.create(ApiService::class.java)

        // 初始化 WebSocket 监听器
        chatWebSocketListener = ChatWebSocketListener(this)

        btnRegister.setOnClickListener {
            val userId = etUserId.text.toString().trim()
            if (userId.isEmpty()) {
                Toast.makeText(this, "Please enter a User ID", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            registerUser(userId)
        }

        btnFetchKeys.setOnClickListener {
            val recipientId = etRecipientId.text.toString().trim()
            if (recipientId.isEmpty()) {
                Toast.makeText(this, "Please enter a Recipient ID", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            fetchRecipientKeys(recipientId)
        }

        btnSendMessage.setOnClickListener {
            val recipientId = etRecipientId.text.toString().trim()
            val messageText = etMessage.text.toString().trim()

            if (recipientId.isEmpty() || messageText.isEmpty()) {
                Toast.makeText(this, "Please enter recipient ID and message", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            sendMessage(recipientId, messageText)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        webSocket?.close(1000, "App closing") // 关闭 WebSocket 连接
    }

    // --- WebSocketListenerCallback 的实现 ---
    override fun onWebSocketConnected() {
        runOnUiThread {
            Toast.makeText(this, "WebSocket connected!", Toast.LENGTH_SHORT).show()
            // 可以在连接成功后发送一个认证消息，让服务器知道当前连接的用户是谁
            val userId = etUserId.text.toString().trim()
            if (userId.isNotEmpty()) {
                val authMessage = JSONObject().apply {
                    put("type", "auth")
                    put("userId", userId)
                }.toString()
                webSocket?.send(authMessage)
                Log.d(TAG, "Sent WebSocket auth message for userId: $userId")
            }
        }
    }
    // 处理认证成功消息
    override fun onWebSocketAuthenticated(userId: String) {
        runOnUiThread {
            Log.d(TAG, "User $userId authenticated successfully via WebSocket.")
            Toast.makeText(this, "Authenticated as $userId!", Toast.LENGTH_SHORT).show()
            // 可以在这里更新UI，例如显示“在线”状态，或者启用消息发送按钮
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    // *** 关键修改在这里：改变方法签名以接收独立参数 ***
    override fun onWebSocketMessage(senderId: String, messageType: Int, encryptedMessageData: String) {
        runOnUiThread {
            Log.d(TAG, "Received structured message from $senderId, type: $messageType")
            // 现在你直接拿到了所有需要的信息
            // 在这里直接调用你的解密和显示消息的方法
            // 例如：
            receiveAndDecryptMessage(senderId, encryptedMessageData, messageType)
        }
    }

    override fun onWebSocketClosing(code: Int, reason: String) {
        runOnUiThread {
            Toast.makeText(this, "WebSocket closing: $reason", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onWebSocketClosed(code: Int, reason: String) {
        runOnUiThread {
            Toast.makeText(this, "WebSocket closed: $reason", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onWebSocketFailure(t: Throwable, response: Response?) {
        runOnUiThread {
            Toast.makeText(this, "WebSocket failure: ${t.message}", Toast.LENGTH_LONG).show()
            Log.e(TAG, "WebSocket failure: ${t.message}", t)
        }
    }
    // --- WebSocketListenerCallback 的实现结束 ---

    @RequiresApi(Build.VERSION_CODES.O)
    private fun registerUser(userId: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            val success = withContext(Dispatchers.IO) {
                performRegistration(userId)
            }

            if (success) {
                Toast.makeText(this@MainActivity3, "User $userId registered successfully!", Toast.LENGTH_LONG).show()
                Log.d(TAG, "User $userId registration successful.")
                // 注册成功后尝试连接 WebSocket
                connectWebSocket(userId)
            } else {
                Toast.makeText(this@MainActivity3, "Registration failed for $userId. Check logs.", Toast.LENGTH_LONG).show()
                Log.e(TAG, "User $userId registration failed.")
            }
        }
    }

    // ... (performRegistration, sendRegistrationRequest 保持不变) ...
    @RequiresApi(Build.VERSION_CODES.O)
    private fun performRegistration(userId: String): Boolean {
        return try {
            Log.d(TAG, "Generating identity key pair for user: $userId")
            val signalProtocolAddress = SignalProtocolAddress(userId, 1)
            identityKeyStore.saveIdentity(signalProtocolAddress, identityKeyPair.publicKey)

            Log.d(TAG, "Generating signed prekey.")
            val signedPreKeyId = secureRandom.nextInt(16777215) + 1
            val signedPreKeyKeyPair = Curve.generateKeyPair()
            val signedPreKeySignature = Curve.calculateSignature(identityKeyPair.privateKey, signedPreKeyKeyPair.publicKey.serialize())
            val signedPreKeyRecord = SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), signedPreKeyKeyPair, signedPreKeySignature)
            signedPreKeyStore.storeSignedPreKey(signedPreKeyId, signedPreKeyRecord)

            Log.d(TAG, "Generating prekeys.")
            val preKeys = mutableListOf<PreKeyRecord>()
            for (i in 0 until 100) {
                val preKeyId = secureRandom.nextInt(16777215) + 1
                val preKey = PreKeyRecord(preKeyId, Curve.generateKeyPair())
                preKeys.add(preKey)
                preKeyStore.storePreKey(preKey.id, preKey)
            }

            val identityKeyPublicBase64 = Base64.getEncoder().encodeToString(identityKeyPair.publicKey.serialize())
            val signedPreKeyPublicBase64 = Base64.getEncoder().encodeToString(signedPreKeyRecord.keyPair.publicKey.serialize())
            val signedPreKeySignatureBase64 = Base64.getEncoder().encodeToString(signedPreKeyRecord.signature)

            val preKeysMap = preKeys.associate {
                it.id.toString() to Base64.getEncoder().encodeToString(it.keyPair.publicKey.serialize())
            }

            val requestBody = JSONObject().apply {
                put("userId", userId)
                put("registrationId", registrationId)
                put("identityKey", identityKeyPublicBase64)
                put("signedPreKey", JSONObject().apply {
                    put("keyId", signedPreKeyRecord.id)
                    put("publicKey", signedPreKeyPublicBase64)
                    put("signature", signedPreKeySignatureBase64)
                })
                put("preKeys", JSONObject(preKeysMap))
            }

            Log.d(TAG, "Sending registration request to server...")
            sendRegistrationRequest(requestBody)

        } catch (e: Exception) {
            Log.e(TAG, "Key generation or network error: ${e.message}", e)
            false
        }
    }

    private fun sendRegistrationRequest(requestBody: JSONObject): Boolean {
        var connection: HttpURLConnection? = null
        return try {
            val url = URL("$SERVER_BASE_URL/register")
            connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json; utf-8")
            connection.doOutput = true

            connection.outputStream.use { os ->
                val input = requestBody.toString().toByteArray(Charsets.UTF_8)
                os.write(input, 0, input.size)
            }

            val responseCode = connection.responseCode
            Log.d(TAG, "Server Response Code: $responseCode")

            responseCode == HttpURLConnection.HTTP_OK
        } catch (e: java.io.IOException) { // 明确捕获 IOException
            Log.e(TAG, "Network error during registration: ${e.message}", e)
            false
        } finally {
            connection?.disconnect()
        }
    }


    @RequiresApi(Build.VERSION_CODES.O)
    private fun fetchRecipientKeys(recipientId: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            try {
                val response = withContext(Dispatchers.IO) {
                    apiService.getUserKeys(recipientId)
                }

                if (response.isSuccessful) {
                    val userKeys = response.body()
                    if (userKeys != null) {
                        Log.d(TAG, "Successfully fetched keys for $recipientId:")
                        Log.d(TAG, "  Identity Key: ${userKeys.identityKey}")
                        Log.d(TAG, "  Signed PreKey ID: ${userKeys.signedPreKey.keyId}")
                        Log.d(TAG, "  Signed PreKey Public: ${userKeys.signedPreKey.publicKey}")
                        Log.d(TAG, "  PreKeys Count: ${userKeys.preKeys.size}")
                        Toast.makeText(this@MainActivity3, "Fetched keys for $recipientId successfully!", Toast.LENGTH_LONG).show()

                        startSession(recipientId, userKeys)

                    } else {
                        Log.e(TAG, "Fetched keys for $recipientId, but response body is null.")
                        Toast.makeText(this@MainActivity3, "Fetched keys for $recipientId, but data is empty.", Toast.LENGTH_LONG).show()
                    }
                } else {
                    val errorBody = response.errorBody()?.string()
                    Log.e(TAG, "Failed to fetch keys for $recipientId. Code: ${response.code()}, Error: $errorBody")
                    Toast.makeText(this@MainActivity3, "Failed to fetch keys for $recipientId. Error: ${errorBody}", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Network or unexpected error when fetching keys: ${e.message}", e)
                Toast.makeText(this@MainActivity3, "Error fetching keys: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun startSession(recipientId: String, userKeys: UserKeysResponse) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // 1. 解析接收方的公钥数据为 libsignal-android 对象
                val recipientIdentityKey = IdentityKey(Base64.getDecoder().decode(userKeys.identityKey), 0) // 0 is iteration
                val recipientSignedPreKeyPublicKey = Curve.decodePoint(Base64.getDecoder().decode(userKeys.signedPreKey.publicKey), 0) // 0 is offset
                val recipientSignedPreKeySignature = Base64.getDecoder().decode(userKeys.signedPreKey.signature)

                // 从预密钥列表中选择一个预密钥 (通常是 ID 最小或最新的，这里简化为第一个)
                val firstPreKeyEntry = userKeys.preKeys.entries.firstOrNull()
                val recipientOneTimePreKeyId: Int? = firstPreKeyEntry?.key?.toInt()
                val recipientOneTimePreKeyPublicKey: ECPublicKey? = firstPreKeyEntry?.value?.let {
                    Curve.decodePoint(Base64.getDecoder().decode(it), 0) // 0 is offset
                }

                // 2. 构建 PreKeyBundle
                val preKeyBundle = PreKeyBundle(
                    userKeys.registrationId, // int registrationId: 接收方的注册ID
                    1, // int deviceId: 接收方的设备ID (假设为 1，因为你的服务器没有返回)
                    recipientOneTimePreKeyId ?: 0, // int preKeyId: 接收方使用的一次性预密钥的ID
                    recipientOneTimePreKeyPublicKey, // ECPublicKey preKeyPublic: 接收方使用的一次性预密钥的公钥
                    userKeys.signedPreKey.keyId, // int signedPreKeyId: 接收方签名预密钥的ID
                    recipientSignedPreKeyPublicKey, // ECPublicKey signedPreKeyPublic: 接收方签名预密钥的公钥
                    recipientSignedPreKeySignature, // byte[] signedPreKeySignature: 接收方签名预密钥的签名
                    recipientIdentityKey // IdentityKey identityKey: 接收方的身份公钥
                )

                // 3. 初始化 SessionBuilder
                val recipientAddress = SignalProtocolAddress(recipientId, 1) // 假设设备 ID 为 1
                val sessionBuilder = SessionBuilder(
                    sessionStore,        // SessionStore sessionStore
                    preKeyStore,         // PreKeyStore preKeyStore
                    signedPreKeyStore,   // SignedPreKeyStore signedPreKeyStore
                    identityKeyStore,    // IdentityKeyStore identityKeyStore
                    recipientAddress     // SignalProtocolAddress remoteAddress
                )

                // 4. 执行 X3DH 握手并建立会话
                sessionBuilder.process(preKeyBundle)

                // 5. 获取 SessionCipher 实例
                val sessionCipher = SessionCipher(
                    sessionStore,        // SessionStore sessionStore
                    preKeyStore,         // PreKeyStore preKeyStore
                    signedPreKeyStore,   // SignedPreKeyStore signedPreKeyStore
                    kyberPreKeyStore,    // KyberPreKeyStore kyberPreKeyStore
                    identityKeyStore,    // IdentityKeyStore identityKeyStore
                    recipientAddress     // SignalProtocolAddress remoteAddress
                )
                sessionCiphers[recipientId] = sessionCipher

                Log.d(TAG, "Session established successfully with $recipientId!")

                // **在这里生成并显示安全号码**
                val localIdentityKey = identityKeyStore.identityKeyPair.publicKey
                val safetyNumber = generateSafetyNumber(localIdentityKey, recipientIdentityKey)
                Log.d(TAG, "Safety Number with $recipientId: $safetyNumber")

                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "Session established with $recipientId! Safety Number: $safetyNumber", Toast.LENGTH_LONG).show()
                }

                if (recipientOneTimePreKeyId != null && recipientOneTimePreKeyId != 0) {
                    Log.d(TAG, "One-Time PreKey with ID ${recipientOneTimePreKeyId} consumed. Need to notify server.")
                    // **重要：通知服务器该 preKey 已被消耗**
                    // 这需要在服务器端实现一个 endpoint 来接收这种通知，并将该 preKey 标记为已使用或删除
                    notifyPreKeyConsumed(recipientId, recipientOneTimePreKeyId)
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error during session setup: ${e.message}", e)
                withContext(Dispatchers.Main) { Toast.makeText(this@MainActivity3, "Session setup failed: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun sendMessage(recipientId: String, messageText: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            val sessionCipher = sessionCiphers[recipientId]
            if (sessionCipher == null) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "No session established with $recipientId. Please fetch keys first.", Toast.LENGTH_LONG).show()
                }
                return@launch
            }

            if (webSocket == null || !webSocket!!.send("")) { // 检查 WebSocket 连接是否就绪
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "WebSocket is not connected. Cannot send message.", Toast.LENGTH_LONG).show()
                }
                return@launch
            }

            try {
                val encryptedMessage = sessionCipher.encrypt(messageText.toByteArray(Charsets.UTF_8))
                val type = encryptedMessage.type
                val ciphertext = Base64.getEncoder().encodeToString(encryptedMessage.serialize())

                Log.d(TAG, "Encrypted message type: $type")
                Log.d(TAG, "Encrypted message Base64: $ciphertext")
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "Message encrypted!", Toast.LENGTH_SHORT).show()
                }

                // 将加密消息通过 WebSocket 发送
                sendEncryptedMessageViaWebSocket(recipientId, type, ciphertext)

            } catch (e: Exception) {
                Log.e(TAG, "Error encrypting message: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "Error encrypting message: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    /**
     * 根据本地和远程身份公钥生成一个可比较的安全号码/指纹。
     * 实际的 Signal 安全号码有更复杂的格式（例如 60 位数字或 QR 码），
     * 这里为了演示目的使用简单的十六进制 SHA-256 哈希。
     *
     * @param localIdentityKey 本地用户的身份公钥。
     * @param remoteIdentityKey 远程用户的身份公钥。
     * @return 双方身份公钥组合的 SHA-256 哈希十六进制字符串。
     */
    @RequiresApi(Build.VERSION_CODES.O)
    private fun generateSafetyNumber(
        localIdentityKey: IdentityKey,
        remoteIdentityKey: IdentityKey
    ): String {
        val localKeyBytes = localIdentityKey.publicKey.serialize()
        val remoteKeyBytes = remoteIdentityKey.publicKey.serialize()

        // 确保以确定性的顺序组合密钥字节，通常是按字典序排序
        val orderedKeys = if (compareByteArrays(localKeyBytes, remoteKeyBytes) < 0) {
            localKeyBytes + remoteKeyBytes
        } else {
            remoteKeyBytes + localKeyBytes
        }

        // 计算组合字节的 SHA-256 哈希
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(orderedKeys)

        // 将哈希值转换为十六进制字符串以便显示
        return hash.joinToString("") { "%02x".format(it) }
    }

    /**
     * 手动实现字节数组的字典序比较，以兼容 minSdk 26。
     * Arrays.compare 需要 API 33。
     */
    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        val minLength = Math.min(a.size, b.size)
        for (i in 0 until minLength) {
            // 将字节转换为无符号整数进行比较
            val diff = (a[i].toUByte().toInt()) - (b[i].toUByte().toInt())
            if (diff != 0) {
                return diff
            }
        }
        // 如果其中一个数组是另一个数组的前缀，则较长的数组更大
        return a.size - b.size
    }

    // --- 新增 WebSocket 相关方法 ---

    private fun connectWebSocket(userId: String) {
        // 1. 如果已有 WebSocket 连接，先尝试关闭它，确保清理旧状态
        if (webSocket != null) {
            Log.d(TAG, "Closing existing WebSocket connection before reconnecting.")
            webSocket?.close(1000, "Reconnecting") // 优雅地关闭旧连接
            webSocket = null // 立即将 webSocket 设置为 null
        }

        // 2. 确保 okHttpClient 被初始化 (虽然你在 onCreate 做了，但重复确保一下无害)
        // okHttpClient = OkHttpClient() // 如果你确定它总是在 onCreate 中初始化一次，这里可以省略

        val request = Request.Builder().url("$WEBSOCKET_URL?userId=$userId").build()
        // 3. 每次都创建新的 WebSocket 实例
        webSocket = okHttpClient.newWebSocket(request, chatWebSocketListener)
        Log.d(TAG, "Attempting to connect WebSocket to $WEBSOCKET_URL for user $userId")
    }

    private fun sendEncryptedMessageViaWebSocket(recipientId: String, messageType: Int, ciphertext: String) {
        val currentUserId = etUserId.text.toString().trim()
        if (webSocket != null && currentUserId.isNotEmpty()) {
            val messageJson = JSONObject().apply {
                put("type", "message") // 消息类型为 "message"
                put("senderId", currentUserId)
                put("recipientId", recipientId)
                put("messageType", messageType) // Signal Protocol 的消息类型 (PREKEY_BUNDLE_TYPE 或 WHISPER_TYPE)
                put("encryptedMessage", ciphertext)
            }
            webSocket?.send(messageJson.toString())
            Log.d(TAG, "Sent encrypted message via WebSocket to $recipientId")
            runOnUiThread {
                etReceivedMessages.append("\nMe to $recipientId: ${etMessage.text.toString()}") // 显示自己发送的消息
                etMessage.text.clear()
            }
        } else {
            Log.e(TAG, "WebSocket not connected or current user ID is empty. Cannot send message.")
            runOnUiThread { Toast.makeText(this, "WebSocket not ready. Message not sent.", Toast.LENGTH_SHORT).show() }
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun receiveAndDecryptMessage(senderId: String, encryptedMessageData: String, messageType: Int) {
        lifecycleScope.launch(Dispatchers.IO) {
            // 获取当前发送方的会话加密器。使用 var 允许在处理过程中更新它。
            var currentSessionCipher = sessionCiphers[senderId]

            try {
                // 解码 Base64 编码的消息数据
                val decodedMessageBytes = Base64.getDecoder().decode(encryptedMessageData)

                // 根据消息类型创建正确的 CiphertextMessage 子类实例
                val ciphertextMessage: CiphertextMessage = when (messageType) {
                    // PREKEY_TYPE 对应 PreKeySignalMessage
                    CiphertextMessage.PREKEY_TYPE -> PreKeySignalMessage(decodedMessageBytes)
                    // WHISPER_TYPE 对应 SignalMessage
                    CiphertextMessage.WHISPER_TYPE -> SignalMessage(decodedMessageBytes)
                    // 如果还需要处理其他类型的消息，例如 PlaintextContent 或 SenderKeyMessage
                    CiphertextMessage.PLAINTEXT_CONTENT_TYPE -> PlaintextContent(decodedMessageBytes)
                    CiphertextMessage.SENDERKEY_TYPE -> SenderKeyMessage(decodedMessageBytes)
                    else -> throw IllegalArgumentException("未知或不支持的消息类型: $messageType")
                }

                var decryptedBytes: ByteArray? = null
                var messageToDisplay: String? = null

                // 核心逻辑：尝试解密消息
                try {
                    // 如果还没有为该发送方创建 SessionCipher，或者当前 SessionCipher 为空
                    if (currentSessionCipher == null) {
                        val senderAddress = SignalProtocolAddress(senderId, 1) // 假设设备 ID 为 1
                        currentSessionCipher = SessionCipher(
                            sessionStore, preKeyStore, signedPreKeyStore, kyberPreKeyStore, identityKeyStore, senderAddress
                        )
                        // 存储新的 SessionCipher 以供后续使用
                        sessionCiphers[senderId] = currentSessionCipher
                    }

                    // 根据 ciphertextMessage 的具体类型调用 SessionCipher.decrypt()
                    // 无论是 PreKeySignalMessage 还是 SignalMessage，都直接传入 decrypt 方法。
                    // Signal 协议库会在 decrypt(PreKeySignalMessage) 内部自动处理会话的建立。
                    decryptedBytes = when (ciphertextMessage) {
                        is PreKeySignalMessage -> currentSessionCipher.decrypt(ciphertextMessage)
                        is SignalMessage -> currentSessionCipher.decrypt(ciphertextMessage)
                        // PlaintextContent 不需要解密，直接获取 body
                        is PlaintextContent -> ciphertextMessage.getBody()
                        // SenderKeyMessage 的解密可能需要更复杂的群组会话管理，这里暂时抛出异常
                        is SenderKeyMessage -> throw UnsupportedOperationException("SenderKeyMessage 解密需要特殊处理，通常用于群组消息。")
                        else -> throw IllegalArgumentException("无法解密此类型的消息: ${ciphertextMessage.javaClass.simpleName}")
                    }

                    messageToDisplay = String(decryptedBytes, Charsets.UTF_8)
                    Log.d(TAG, "从 $senderId 解密消息: $messageToDisplay")

                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity3, "收到来自 $senderId 的消息: $messageToDisplay", Toast.LENGTH_LONG).show()
                        etReceivedMessages.append("\n$senderId: $messageToDisplay")
                    }

                } catch (e: NoSessionException) {
                    // 如果 SessionCipher.decrypt() 仍然抛出 NoSessionException，这意味着会话确实没有建立。
                    // 并且根据 SessionBuilder 的 Javadoc，我们不能直接用 SessionBuilder.process(PreKeySignalMessage)。
                    // 这种情况通常不应该发生，因为 decrypt(PreKeySignalMessage) 旨在处理会话建立。
                    // 但如果发生了，说明某种状态异常或消息顺序不对。
                    Log.e(TAG, "解密消息时没有会话，且未能通过 decrypt 自动建立会话: ${e.message}", e)
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity3, "无法解密来自 $senderId 的消息: 会话未建立或异常。", Toast.LENGTH_LONG).show()
                    }
                    return@launch
                }

            } catch (e: DuplicateMessageException) {
                Log.w(TAG, "收到来自 $senderId 的重复消息。跳过解密。", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "收到来自 $senderId 的重复消息。", Toast.LENGTH_SHORT).show()
                }
            } catch (e: InvalidMessageException) {
                Log.e(TAG, "来自 $senderId 的无效消息: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "来自 $senderId 的无效消息: ${e.message}", Toast.LENGTH_LONG).show()
                }
            } catch (e: InvalidKeyException) {
                Log.e(TAG, "来自 $senderId 消息的无效密钥: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "来自 $senderId 消息的无效密钥: ${e.message}", Toast.LENGTH_LONG).show()
                }
            } catch (e: UntrustedIdentityException) {
                Log.e(TAG, "来自 $senderId 消息的不可信身份: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "来自 $senderId 消息的不可信身份: ${e.message}。请验证安全码。", Toast.LENGTH_LONG).show()
                }
            } catch (e: UnsupportedOperationException) {
                Log.e(TAG, "不支持的消息类型解密: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "不支持的消息类型解密: ${e.message}", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "解密来自 $senderId 的消息时发生通用错误: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "解密来自 $senderId 的消息时发生错误: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    // 新增：通知服务器预密钥已被消耗
    private fun notifyPreKeyConsumed(recipientId: String, preKeyId: Int) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val requestBody = JSONObject().apply {
                    put("userId", recipientId)
                    put("preKeyId", preKeyId)
                }
                val url = URL("$SERVER_BASE_URL/consume_prekey")
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.setRequestProperty("Content-Type", "application/json; utf-8")
                connection.doOutput = true

                connection.outputStream.use { os: OutputStream ->
                    val input = requestBody.toString().toByteArray(Charsets.UTF_8)
                    os.write(input, 0, input.size)
                }

                val responseCode = connection.responseCode
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    Log.d(TAG, "Successfully notified server that preKey $preKeyId for $recipientId was consumed.")
                } else {
                    Log.e(TAG, "Failed to notify server about preKey consumption. Code: $responseCode")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error notifying server about preKey consumption: ${e.message}", e)
            }
        }
    }
}
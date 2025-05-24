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
import okio.IOException
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

// 新增 Signal Protocol 相关的导入
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.ecc.ECPublicKey // 导入 ECPublicKey
import org.signal.libsignal.protocol.state.impl.InMemorySessionStore // 导入 InMemorySessionStore
import org.signal.libsignal.protocol.state.impl.InMemoryKyberPreKeyStore // 导入 InMemoryKyberPreKeyStore

import java.security.MessageDigest // **新增导入**
import java.util.Arrays // **新增导入**

class MainActivity3 : AppCompatActivity() {

    private val TAG = "SignalChatApp"
    private val SERVER_BASE_URL = "http://192.168.1.196:5000" // 确保这是你的服务器 IP

    private lateinit var etUserId: EditText
    private lateinit var btnRegister: Button
    private lateinit var etRecipientId: EditText
    private lateinit var btnFetchKeys: Button
    // 新增：发送消息 UI
    private lateinit var etMessage: EditText
    private lateinit var btnSendMessage: Button

    private lateinit var identityKeyPair: IdentityKeyPair
    private var registrationId: Int = 0
    private lateinit var identityKeyStore: InMemoryIdentityKeyStore
    private val preKeyStore = InMemoryPreKeyStore()
    private val signedPreKeyStore = InMemorySignedPreKeyStore()
    private val secureRandom = SecureRandom()
    private val sessionStore = InMemorySessionStore()
    private val kyberPreKeyStore = InMemoryKyberPreKeyStore()

    private lateinit var apiService: ApiService

    // 新增：用于存储已建立会话的 SessionCipher
    // Key: 接收方 userId, Value: SessionCipher
    private val sessionCiphers: MutableMap<String, SessionCipher> = mutableMapOf()

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

    @RequiresApi(Build.VERSION_CODES.O)
    private fun registerUser(userId: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            val success = withContext(Dispatchers.IO) {
                performRegistration(userId)
            }

            if (success) {
                Toast.makeText(this@MainActivity3, "User $userId registered successfully!", Toast.LENGTH_LONG).show()
                Log.d(TAG, "User $userId registration successful.")
            } else {
                Toast.makeText(this@MainActivity3, "Registration failed for $userId. Check logs.", Toast.LENGTH_LONG).show()
                Log.e(TAG, "User $userId registration failed.")
            }
        }
    }

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
        } catch (e: IOException) {
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
                    // 你也可以在 UI 上显示这个安全号码，让用户手动比较
                }

                if (recipientOneTimePreKeyId != null) {
                    Log.d(TAG, "One-Time PreKey with ID ${recipientOneTimePreKeyId} consumed. Need to notify server.")
                    // TODO: Implement server notification for pre-key consumption
                }

            } catch (e: Exception) { // 统一捕获 Exception，便于调试
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

            try {
                // 加密消息
                val encryptedMessage = sessionCipher.encrypt(messageText.toByteArray(Charsets.UTF_8))
                val type = encryptedMessage.type
                val ciphertext = Base64.getEncoder().encodeToString(encryptedMessage.serialize())

                Log.d(TAG, "Encrypted message type: $type")
                Log.d(TAG, "Encrypted message Base64: $ciphertext")
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "Message encrypted!", Toast.LENGTH_SHORT).show()
                }

                // ⚠️ 下一步：将加密后的消息发送到服务器
                // 你需要实现一个消息转发机制，服务器接收加密消息，然后推送给接收方
                // 示例：sendMessageToServer(recipientId, type, ciphertext)
                Log.d(TAG, "TODO: Send encrypted message to server for $recipientId")

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

    // TODO: 接收消息和解密消息的逻辑
    // 当你从服务器收到加密消息时，需要用 sessionCipher.decrypt() 进行解密
    // 例如：
    /*
    @RequiresApi(Build.VERSION_CODES.O)
    private fun receiveAndDecryptMessage(senderId: String, encryptedMessageData: String, messageType: Int) {
        lifecycleScope.launch(Dispatchers.IO) {
            val sessionCipher = sessionCiphers[senderId]
            if (sessionCipher == null) {
                Log.e(TAG, "No session established with $senderId to decrypt message.")
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "No session with $senderId to decrypt message.", Toast.LENGTH_LONG).show()
                }
                return@launch
            }

            try {
                val ciphertextMessage: CiphertextMessage = when(messageType) {
                    CiphertextMessage.PREKEY_BUNDLE_TYPE -> PreKeyBundleMessage(Base64.getDecoder().decode(encryptedMessageData))
                    CiphertextMessage.WHISPER_TYPE -> WhisperMessage(Base64.getDecoder().decode(encryptedMessageData))
                    else -> throw IllegalArgumentException("Unknown message type: $messageType")
                }

                val decryptedBytes = sessionCipher.decrypt(ciphertextMessage)
                val decryptedMessage = String(decryptedBytes, Charsets.UTF_8)

                Log.d(TAG, "Decrypted message from $senderId: $decryptedMessage")
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "Received from $senderId: $decryptedMessage", Toast.LENGTH_LONG).show()
                    // 在 UI 上显示消息
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error decrypting message: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity3, "Error decrypting message from $senderId: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }
    */
}

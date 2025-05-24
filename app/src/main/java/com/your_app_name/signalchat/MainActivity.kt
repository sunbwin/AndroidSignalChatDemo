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
import retrofit2.Retrofit // 导入 Retrofit
import retrofit2.converter.gson.GsonConverterFactory // 导入 GsonConverterFactory

class MainActivity : AppCompatActivity() {

    private val TAG = "SignalChatApp"
    private val SERVER_BASE_URL = "http://192.168.1.196:5000" // 确保这是你的服务器 IP

    private lateinit var etUserId: EditText
    private lateinit var btnRegister: Button
    private lateinit var etRecipientId: EditText // 新增：接收方用户 ID 输入框
    private lateinit var btnFetchKeys: Button // 新增：获取密钥按钮

    private lateinit var identityKeyPair: IdentityKeyPair
    private var registrationId: Int = 0
    private lateinit var identityKeyStore: InMemoryIdentityKeyStore
    private val preKeyStore = InMemoryPreKeyStore()
    private val signedPreKeyStore = InMemorySignedPreKeyStore()
    private val secureRandom = SecureRandom()

    private lateinit var apiService: ApiService // 新增：Retrofit API 服务实例

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etUserId = findViewById(R.id.etUserId)
        btnRegister = findViewById(R.id.btnRegister)
        etRecipientId = findViewById(R.id.etRecipientId) // 初始化
        btnFetchKeys = findViewById(R.id.btnFetchKeys) // 初始化

        val ecKeyPair = Curve.generateKeyPair()
        identityKeyPair = IdentityKeyPair(
            IdentityKey(ecKeyPair.publicKey.serialize()),
            ECPrivateKey(ecKeyPair.privateKey.serialize())
        )
        registrationId = secureRandom.nextInt(16380) + 1

        identityKeyStore = InMemoryIdentityKeyStore(identityKeyPair, registrationId)

        // 初始化 Retrofit
        val retrofit = Retrofit.Builder()
            .baseUrl(SERVER_BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
        apiService = retrofit.create(ApiService::class.java) // 创建 ApiService 实例

        btnRegister.setOnClickListener {
            val userId = etUserId.text.toString().trim()
            if (userId.isEmpty()) {
                Toast.makeText(this, "Please enter a User ID", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            registerUser(userId)
        }

        // 新增：为获取密钥按钮设置点击监听器
        btnFetchKeys.setOnClickListener {
            val recipientId = etRecipientId.text.toString().trim()
            if (recipientId.isEmpty()) {
                Toast.makeText(this, "Please enter a Recipient ID", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            fetchRecipientKeys(recipientId)
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun registerUser(userId: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            val success = withContext(Dispatchers.IO) {
                performRegistration(userId)
            }

            if (success) {
                Toast.makeText(this@MainActivity, "User $userId registered successfully!", Toast.LENGTH_LONG).show()
                Log.d(TAG, "User $userId registration successful.")
            } else {
                Toast.makeText(this@MainActivity, "Registration failed for $userId. Check logs.", Toast.LENGTH_LONG).show()
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

    // 新增：获取接收方公钥的函数
    private fun fetchRecipientKeys(recipientId: String) {
        lifecycleScope.launch(Dispatchers.Main) {
            try {
                val response = withContext(Dispatchers.IO) {
                    apiService.getUserKeys(recipientId) // 调用 Retrofit 服务
                }

                if (response.isSuccessful) {
                    val userKeys = response.body()
                    if (userKeys != null) {
                        Log.d(TAG, "Successfully fetched keys for $recipientId:")
                        Log.d(TAG, "  Identity Key: ${userKeys.identityKey}")
                        Log.d(TAG, "  Signed PreKey ID: ${userKeys.signedPreKey.keyId}")
                        Log.d(TAG, "  Signed PreKey Public: ${userKeys.signedPreKey.publicKey}")
                        Log.d(TAG, "  PreKeys Count: ${userKeys.preKeys.size}")
                        Toast.makeText(this@MainActivity, "Fetched keys for $recipientId successfully!", Toast.LENGTH_LONG).show()

                        // ⚠️ 这里是下一步 X3DH 密钥交换的入口
                        // 你将在这里使用 userKeys 对象中的数据来启动 Signal Protocol 的会话建立
                        // 例如：startSession(recipientId, userKeys)
                    } else {
                        Log.e(TAG, "Fetched keys for $recipientId, but response body is null.")
                        Toast.makeText(this@MainActivity, "Fetched keys for $recipientId, but data is empty.", Toast.LENGTH_LONG).show()
                    }
                } else {
                    val errorBody = response.errorBody()?.string()
                    Log.e(TAG, "Failed to fetch keys for $recipientId. Code: ${response.code()}, Error: $errorBody")
                    Toast.makeText(this@MainActivity, "Failed to fetch keys for $recipientId. Error: ${errorBody}", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Network or unexpected error when fetching keys: ${e.message}", e)
                Toast.makeText(this@MainActivity, "Error fetching keys: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }
}

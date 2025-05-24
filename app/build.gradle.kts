@file:Suppress("UnstableApiUsage")

import org.gradle.api.JavaVersion // 确保导入 JavaVersion

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.kapt") // Room 数据库需要
    id("org.jetbrains.kotlin.plugin.compose") // Compose 需要
    // 如果不需要以下插件，可以移除
    // id("androidx.navigation.safeargs")
    // id("kotlin-parcelize")
    // id("com.squareup.wire")
    // id("translations")
    // id("licenses")
}

android {
    namespace = "com.your_app_name.signalchat" // 替换为你的应用包名
    compileSdk = 36 // 推荐使用 34 或更高版本，与 targetSdk 保持一致

    defaultConfig {
        applicationId = "com.your_app_name.signalchat" // 替换为你的应用包 ID
        minSdk = 24 // 最低 SDK 版本，为了脱糖，建议 24 或更高
        targetSdk = 34 // 目标 SDK 版本
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" // 如果有测试，保留
        vectorDrawables.useSupportLibrary = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false // 发布版本通常设置为 true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    // 核心：强制使用 Java 17 编译和 JVM 目标，并确保脱糖正确启用
    compileOptions {
        isCoreLibraryDesugaringEnabled = true // 关键：启用核心库脱糖
        sourceCompatibility = JavaVersion.VERSION_17 // 关键：设置为 Java 17
        targetCompatibility = JavaVersion.VERSION_17 // 关键：设置为 Java 17
    }
    kotlinOptions {
        jvmTarget = "17" // 关键：设置为 "17"
    }

    buildFeatures {
        viewBinding = true // 启用 View Binding
        compose = true // 启用 Compose
        buildConfig = true // 如果需要 BuildConfig 字段，保留
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.4" // 确保与你的 Compose 库版本兼容
    }

    packaging {
        jniLibs {
            excludes += setOf(
                "**/*.dylib", // macOS 动态库
                "**/*.dll" // Windows 动态库
            )
        }
        resources {
            excludes += setOf(
                "META-INF/LICENSE",
                "META-INF/LICENSE.md",
                "META-INF/NOTICE",
                "META-INF/LICENSE-notice.md",
                "META-INF/proguard/androidx-annotations.pro",
                "**/*.dylib",
                "**/*.dll"
            )
        }
    }

    defaultConfig {
        // ... 保留你的 applicationId, minSdk, targetSdk, versionCode, versionName 等
        buildConfigField("String", "APP_VERSION", "\"${versionName}\"") // 示例：添加你自己的 BuildConfig 字段
    }
}

dependencies {
    implementation(libs.androidx.activity)
    // 核心库脱糖依赖
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.3")

    // Compose
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation(platform("androidx.compose:compose-bom:2024.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling") // 调试工具

    // AndroidX 核心依赖
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.activity:activity-ktx:1.10.1") // 确保是这个版本

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")

    // OkHttp
    implementation("com.squareup.okhttp3:okhttp:4.9.3")

    // Kotlin Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")

    // ViewModel and LiveData
    val lifecycleKtxVersion = "2.7.0"
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:$lifecycleKtxVersion")
    implementation("androidx.lifecycle:lifecycle-livedata-ktx:$lifecycleKtxVersion")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:$lifecycleKtxVersion")

    // Room Database
    val roomVersion = "2.6.1"
    implementation("androidx.room:room-runtime:$roomVersion")
    kapt("androidx.room:room-compiler:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")

    // Retrofit
    val retrofitVersion = "2.9.0"
    implementation("com.squareup.retrofit2:retrofit:$retrofitVersion")
    implementation("com.squareup.retrofit2:converter-gson:$retrofitVersion")

    // Socket.IO Client
    val socketioVersion = "2.0.1"
    val okioVersion = "2.8.0"
    implementation("io.socket:socket.io-client:$socketioVersion")
    implementation("com.squareup.okio:okio:$okioVersion")

    // Logging (Timber)
    implementation("com.jakewharton.timber:timber:5.0.1")

    // Signal Protocol 库
    implementation("org.signal:libsignal-android:0.72.1")
    implementation("org.signal:libsignal-client:0.72.1")

    // Android Security Crypto
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}

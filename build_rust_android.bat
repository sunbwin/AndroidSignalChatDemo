@echo off
REM 设置工作目录
cd rust

REM 执行 cargo ndk 编译
cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 ^
  -o ..\app\src\main\jniLibs ^
  build --release

REM 返回原目录
cd ..

echo:
echo ✅ Rust 构建完成并输出至 app\src\main\jniLibs\
pause

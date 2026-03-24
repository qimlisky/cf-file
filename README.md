##Cloudflare Worker 脚本 - 文件托管服务（完整版：双页面批量下载）
绑定KV命名空间: FILE_STORAGE  
环境变量: TOTP_SECRET  
在main页面是文件管理页面，使用的是totp验证  
可选的生成otp生成器，Base32编码, SHA1  周期30s

```
https://www.lddgo.net/encrypt/otp-code-generate
```

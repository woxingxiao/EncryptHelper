[![](https://jitpack.io/v/woxingxiao/EncryptHelper.svg)](https://jitpack.io/#woxingxiao/VectorCompatTextView)
[![API](https://img.shields.io/badge/API-9%2B-blue.svg?style=flat)](https://android-arsenal.com/api?level=18)
[![License](http://img.shields.io/badge/License-Apache%202.0-brightgreen.svg?style=flat)](https://opensource.org/licenses/Apache-2.0)

# EncryptHelper
Android data localized safety encryption/decryption tool.
数据安全本地化加密解密工具。

![demo1](https://github.com/woxingxiao/EncryptHelper/blob/master/screenshot/demo1.jpg)

# Theory
AES（非对称加密）的Key想要存在KeyStore里，需要Api 23才被支持，但是RSA（非对称加密）不受限制（Api >= 18）。
因此用RSA加密AES的密钥保存到本地（如SharedPreferences），需要时解密得到AES的密钥，在用AES密钥来加解密。
过程：
1. 使用KeyStore生成随机的RSA Key（非对称加密密钥）；
2. 生成AES Key（对称加密密钥），并用RSA PublicKey（公钥）加密后存入SharedPreferences；
3. 从SharedPreferences取出AES Key，并用RSA PrivateKey（私钥）解密，用AES Key来加密和解密。

# Usage (Api >= 18)
```java
EncryptHelper mEncryptHelper = new EncryptHelper(getApplicationContext());

mEncryptHelper.encrypt(plainText);

mEncryptHelper.decrypt(encryptedText);
```

# License
```
   Copyright 2017 woxingxiao

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
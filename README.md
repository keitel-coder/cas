## 中心认证服务设计

**目录**
**1. 账号体系中密码的加密**
**2. CAS：中心认证服务**

### 一、账号体系中密码的加密
> 如果用户密码体系本身设计不安全，即使登录过程中设计的再安全也无法弥补。因此为了账号密码安全，账号密码需要经过程序盐值+数据库盐值混合加密后保存至数据库。为了降低数据库被托库导致用户密码泄露风险，用户密码相关信息与用户信息分表（甚至分库）存放，以下为用户账号密码加密设计。

##### 1. 用户信息表

| 列名| 说明 | 备注 |
| --- | --- | --- |
| UserId | 用户id | 用户唯一标志 |
| Others | 用户其它信息 | 不包含密码相关的其它字段 |
>为保证用户密码信息在用户信息被泄露时的安全（如sql注入查询时），不将用户密码相关信息与用户基本信息混合存放，也方便对用户密码表的权限做控制。

##### 2. 用户盐值表

| 列名| 说明 | 备注 |
| --- | --- | --- |
| UserId | 用户id | 用户唯一标志 |
| Salt | 用户密码盐值 | 用户每次修改密码时随机生成的字符串 |
| CreateTime | 盐值生成时间 |  |
>密码的盐值应足够随机，长度足够，可以使用SHA512(GUID)，在用户修改密码时最好密码盐值也重新生成。

##### 3. 用户密码表
| 列名| 说明 | 备注 |
| --- | --- | --- |
| UserId | 用户id | 用户唯一标志 |
| Password | 用户密码 | 经过加密后的用户密码 |
>用户密码需要使用SHA256以上算法将（用户Id+用户密码盐值+程序中的固定盐值+用户密码）混合运算，具体混合方法可以依据情况而定。例：SHA512(用户Id的反转+用户密码的反转+程序固定密码盐值+随机的用户密码盐值)。
> 程序的固定密码盐值可以通过配置文件配置，开发环境与测试环境应不同。

## 二、CAS：中心认证服务
>对于使用同一套用户体系的不同系统，为了减少用户在各系统之间做相同登录操作，也为了减少用户账号密码在各平台泄露的风险，因此需要对用户账号登录及相关敏感操作做集中管理。CAS与SSO的区别为SSO是达到的目的，CAS是实现方式。

>本设计遵循的CAS协议规范请查看 [链接](https://apereo.github.io/cas/5.1.x/protocol/CAS-Protocol-Specification.html)。

### 名称解释：
    以下为后文可能提到的名词解释
* CAS：全称Central Authentication Service，中心认证服务，提供各应用系统做账号认证的服务站点。
* SSO：Single Sign On，单点登录。
* SLO：Single Logout，单点登出。
* CAS Server：中心认证服务服务端。
* CAS Client：中心认证服务客户端，指各应用系统。
* Ticket-granting cookie(TGC) ：存放用户身份认证凭证的 cookie ，在浏览器和 CAS Server间通讯时使用，并且只能基于安全通道传输（ Https ），是 CAS Server 用来明确用户身份的凭证。
* Service ticket(ST) ：服务票据，服务的惟一标识码 , 由 CAS Server 发出（ Http 传送），通过客户端浏览器到达业务服务器端；一个特定的服务只能有一个惟一的 ST 。
* Proxy-Granting ticket （ PGT ）：由 CAS Server 颁发给拥有 ST 凭证的服务， PGT 绑定一个用户的特定服务，使其拥有向 CAS Server 申请，获得 PT 的能力。
* Proxy Ticket (PT) ：是应用程序代理用户身份对目标程序进行访问的凭证。暂时用不到。

### CAS站点设计
#### Controller方法

    CAS服务需要对外提供以下方法，即对外的Https服务。

* /login	中心认证服务站点的登录方法，有时可能需要同时提供用户名+密码和手机号两种认证方式登录。
* /logout	登出认证中心服务站点。
* /serviceValidate	对service ticket的验证
* /proxyValidate	对proxy ticket的验证[暂时用不到]

##### /login
###### 请求参数：userName, password
###### 返回：返回登录页或返回来源页（同时返回st）

###### 方法内部流程：
1. 用户从客户端跳转到CAS登录地址，判断是否登录，如果已登录，执行步骤3。
2. 如用户未登录，显示登录页面，用户在登录页提交正确登录信息后执行步骤3。
3. 判断用户跳转过来的站点是否属于客户端白名单，如果属于则携带Service ticket返回原请求页，否则跳转到CAS站点默认页面。

###### 方法详细细节：
**用户提交登录信息，登录信息认证成功后的操作：**

1. 随机生成key作为缓存主键，将用户id、用户登录时间、登录失效时间为内容放入缓存，以登录失效时间作为缓存的失效时间。
>缓存内容示例："xsfggsg-sdhsh-dxhds-shsdh-csdhs":{userId:1, userName:"admin",createTime:"2019-08-18 00:00",expireTime:"2019-08-19 00:00"}
2. 将第1步随机生成的key、用户id、创建时间、过期时间作为json对象经对称加密后的Base64字符串写入Cookie，cookie名为tgc。
>示例：用户id为1的用户登录后，需要写入cookie 的登录信息为{userId:1, sessionId:"xsfggsg-sdhsh-dxhds-shsdh-csdhs",createTime:"2019-08-18 00:00:00",expireTime:"2019-08-19 00:00:00"}，AES加密后为：U2FsdGVkX1+p3uI4E0llEYSHm7/2jBfbftklVtFJBrjZJHjoAsP2ylhgl1d6YW3K
mBH8Q+fh5CjqQYGUeWOtGX2t9Dz9ynBcOBSyINn64uUwLkXBoNtOXAe9DlaU+YvA
EsPp0ji1Qkoe32kgXDLt3IPDRmiFKzfES+OQfMfpsXTCx5oDPTpNZzXetKvpgEl5，Base64加密后为VTJGc2RHVmtYMStwM3VJNEUwbGxFWVNIbTcvMmpCZmJmdGtsVnRGSkJyalpKSGpvQXNQMnlsaGdsMWQ2WVczSwptQkg4UStmaDVDanFRWUdVZVdPdEdYMnQ5RHo5eW5CY09CU3lJTm42NHVVd0xrWEJvTnRPWEFlOURsYVUrWXZBCkVzUHAwamkxUWtvZTMya2dYREx0M0lQRFJtaUZLemZFUytPUWZNZnBzWFRDeDVvRFBUcE5aelhldEt2cGdFbDU=，因此将最终Base64的字符存入名为tgc的cookie。

3. 根据白名单（白名单根据需求可以放数据库也可以放程序中）请求登录的host判断是否为授权登录的站点，如果为白名单站点，则进入下一步，否则显示CAS服务默认页。
4. 生成Service ticket：随机生成唯一的key（判断是否在缓存中已存在），内容为当前登录用户Id+服务票据创建时间+服务票据失效时间（当前时间+5分钟）+登录站点。示例：{userId:1,createTime:"2019-08-18 00:00:00",expireTime:"2019-08-19 00:05:00",host:site1.yitu.com}
5. 将第4步生成的Service ticket通过url返回给请求授权地址，如：http://site1.yitu.com/login?st=VmtYMThjbDh5MzVhcU12YkZtdFI4RTNm
6. 判断是否已登录CAS：获取用户cookie中是否存在tgc名称的cookie，如果存在则将内容Base64还原后使用DES解密，如Base64还原失败或解密失败，则为未登录。将解密后的json反序列化后判断是否已过期（失效时间字段），如已过期则返回失败。根据sessionId从缓存中取出内容，如果缓存不存在或缓存中的内容（用户id、创建时间、失效时间）不一致，则为未登录，完全相等则为已登录。**【此过程需要提取为方法】**


##### /logout
###### 请求参数：无
###### 返回：登录页或来源页
###### 方法内部流程

1. 判断用户是否已登录CAS（具体判断登录方法请参考登录时的操作），未登录跳到登录页或返回请求页。
2. 已登录CAS时，将登录时设置的cookie及缓存清除，如果有需要，还需要将各客户端站点的登录信息清除（通过jsonp）

##### /serviceValidate
###### 请求参数：serviceTicket
###### 返回：错误消息或用户信息
###### 方法内部流程

1. CAS Client使用url中的st（CAS登录返回）请求CAS的serviceValidate方法，CAS判断st是否存在且有效，如无效或已过期则返回错误消息，这一步无论st是否有效。
2. 校验用户st有效后，随机生成字符（唯一）作为代理授权票据Proxy-Granting ticket （ PGT ），连同用户信息返回。缓存内容示例：{userId:1,userName:"admin",pgt:"MU3dxNTRRQWVhc3B2SVBlZ0dTK3FHS2NPY3o4WTZhM0tqZUk1UFE2V2cvWVB1a3IvdFZMCnVBV0"}

**以上均为同步操作方法，如果需要异步登录/登出/判断是否已登录，需要使用JSONP实现，区别在于返回参数不同，其它大致相同。**

#### AccountService 类
**Boolean validatePassword(Integer userId,String password)** 
判断用户密码是否正确方法。

**UserData getUserData(String cookieVal)** 
获取cookie中的用户信息，参数为cookie中获取到的登录信息，校验成功则返回序列化后的对象，否则返回null。

**Boolean isLogin(Integer userId, String sessionId, DateTime createTime, DateTime expireTime)**
判断用户是否已登录。

#### CryptoUtils 加密工具类
**String encryptedAES(String str, String password)**
AES加密方法

**String decryptAES(String str, String password)**
AES解密方法

**String encryptedBase64(String str, String password)**
Base64加密方法

**String decryptBase64(String str, String password)**
Base64解密方法

**String SHA512(String str)**
SHA512加密方法

#### Redis 工具类
**String generateTicketGrantingSessionId()**
生成CAS登录会话SessionId的方法，需要在缓存中唯一

**void insertTicketGrantingSession(String sessionId,Integer userId, String userName, DateTime createTime, DateTime expireTime)**
插入CAS登录会话Session到缓存的方法

**String generateServiceTicket()**
生成ServiceTicket，需要在缓存中唯一

 **void insertTicketGrantingSession(String serviceTicket,Integer userId,  String host, DateTime createTime, DateTime expireTime)**
插入ServiceTicket到缓存的方法


#### **未完待续...**

此项目参考[lizhongyue248](https://github.com/lizhongyue248/spring-security-oauth2-demo)的spring-security-oauth2项目
，使用 mysql 存储客户端信息，使用 jwt 令牌获取资源
### 技术栈
>1. springboot2+
>2. mysql(存储客户端)
>3. jwt(对称和非对称加密方式token)
>4. oauth2(使用spring security 的oauth2实现api，而非oauth2的原生api)
### 如何运行
#### 创建客户端信息表
数据库初始化(数据库名 auth)
执行oauth_client_details.sql文件，包含一张 oauth-client-details 表用于存储 client令牌
```
create table if not exists oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);
```

| 列名 | 类型 | 描述 |
| ---- | ---- | ---- |
| client_id（主键）	| VARCHAR(256)	| 主键,必须唯一,不能为空. 用于唯一标识每一个客户端(client); 在注册时必须填写(也可由服务端自动生成). 对于不同的grant_type,该字段都是必须的。在实际应用中的另一个名称叫appKey,与client_id是同一个概念 |
| resource_ids | VARCHAR(256) |	客户端所能访问的资源id集合,多个资源时用逗号(,)分隔 |
| client_secret	| VARCHAR(256)	| 用于指定客户端(client)的访问密匙; 在注册时必须填写(也可由服务端自动生成). 对于不同的grant_type,该字段都是必须的. 在实际应用中的另一个名称叫appSecret,与client_secret是同一个概念 |
| scope	| VARCHAR(256)	| 指定客户端申请的权限范围,可选值包括read,write,trust;若有多个权限范围用逗号(,)分隔,如: “read,write” |
| authorized_grant_types	| VARCHAR(256)	| 指定客户端支持的grant_type,可选值包括authorization_code,password,refresh_token,implicit,client_credentials,若支持多个grant_type用逗号(,)分隔,如: “authorization_code,password”在实际应用中,当注册时,该字段是一般由服务器端指定的,而不是由申请者去选择的 |
| web_server_redirect_uri	| VARCHAR(256)	| 客户端的重定向URI,可为空, 当grant_type为authorization_code或implicit时, 在Oauth的流程中会使用并检查与注册时填写的redirect_uri是否一致 |
| authorities	| VARCHAR(256)	| 指定客户端所拥有的Spring Security的权限值,可选, 若有多个权限值,用逗号(,)分隔, 如: "ROLE_ADMIN" |
| access_token_validity	| INTEGER	| 设定客户端的access_token的有效时间值(单位:秒),可选, 若不设定值则使用默认的有效时间值(60 * 60 * 12, 12小时) |
| refresh_token_validity	| INTEGER	| 设定客户端的refresh_token的有效时间值(单位:秒),可选, 若不设定值则使用默认的有效时间值(60 * 60 * 12, 12小时) |
| additional_information	| VARCHAR(4096)	| 这是一个预留的字段,在Oauth的流程中没有实际的使用,可选,但若设置值,必须是JSON格式的数据,在实际应用中, 可以用该字段来存储关于客户端的一些其他信息 |
| autoapprove	| VARCHAR(256)	| 设置用户是否自动Approval操作, 默认值为 ‘false’, 可选值包括 ‘true’,‘false’, ‘read’,‘write’该字段只适用于grant_type="authorization_code"的情况,当用户登录成功后,若该值为’true’或支持的scope值,则会跳过用户Approve的页面,直接授权 |

#### Method 1 使用Postman 开发测试用
1. 启动认证服务器
入口App.java中运行 App.main()
2. 获取授权码 authorization_code
1) 浏览器中输入
>http://localhost:8000/oauth/authorize?response_type=code&client_id=oauth2&redirect_uri=http://example.com&scope=all
2) 输入用户名和密码(admin/admin)登录并同意授权
认证服务器会在浏览器返回code
>http://example.com/?code=8hvFW2
3) 获取token(postman中操作)
>1. POST请求方式: http://localhost:8000/oauth/token
>2. Params面版参数

| Key | VALUE |
| :---:|:---: |
| grant_type | authorization_code |
| client_id | oauth2|
| scope | all |
| redirect_uri | http://example.com |
| code | 8hvFW2 |
>3. Authorization面版参数

| KEY | VALUE |
| :---:|:---: |
| 左侧Type | Basic Auth |
| 右侧Username | oauth2 |
| 右侧Password | oauth2 |

输入以上Authorization面版内容后在Header 页版会自动出现以下内容
>KEY 为 Authorization ，VALUE 为 Basic b2F1dGgyOm9hdXRoMg==
 
格式为 Authorization: Basic base64编码的 client_id:client_secret
4) 使用 token 访问资源服务器 resource server获取资源
>1. GET请求 http://localhost:9000/auth/me
>2. Authorization面版，左侧TYPE选择Bearer Token，右侧 Token 填写生成的 token

Authorization面版填写后header面版会自动会生成以下内容
 >KEY 为 Authorization，VALUE 为 Bearer eyJhbGciOiJ.SUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzb3

5) refresh_token 授权类型的使用
授权服务器安全需要手动把 UserDetailService 手动注入
AuthorizationServerEndpointsConfigurer.userDetailsService(userDetailsService)
>1. POST请求 http://localhost:8000/oauth/token
>2. Authorization面版参数
  
  | KEY | VALUE |
  | :---:|:---: |
  | 左侧Type | Basic Auth |
  | 右侧Username | oauth2 |
  | 右侧Password | oauth2 |
  
>3. Body面版
选择 x-www-form-urlencoded 选项,参数如下
 
   | KEY | VALUE |
   | :---:|:---: |
   | grant_type | refresh_token |
   | refresh_token | YOUR_refresh_token |
 
 输入以上Authorization面版和Body面版后内容后在Header 页版会自动出现以下内容
 >KEY 为 Authorization ，VALUE 为 Basic b2F1dGgyOm9hdXRoMg==
 >KEY 为 Content-Type , VALUE  为 application/x-www-form-urlencoded
 
6) oauth/check_token 端点的使用
>1. POST 请求 http://localhost:8000/oauth/check_token
>2. Authorization面版参数
   
   | KEY | VALUE |
   | :---:|:---: |
   | 左侧Type | Basic Auth |
   | 右侧Username | oauth2 |
   | 右侧Password | oauth2 |
   
>3. Body面版参数
选择 x-www-form-urlencoded 选项,参数如下
 
   | KEY | VALUE |
   | :---:|:---: |
   | token | YOUR_token |
  
 输入以上Authorization面版和Body面版内容后在Header 页版会自动出现以下内容
 >KEY 为 Authorization ，VALUE 为 Basic b2F1dGgyOm9hdXRoMg==
 >KEY 为 Content-Type , VALUE  为 application/x-www-form-urlencoded
 
 ###  Method 2 client-one和 client-two 两个 client开发测试
 http://localhost:8081/clientOne/list
 http://localhost:8082/clientTwo/list
 
#### spring security oauth2 工作流程
流程源自[这里](http://terasolunaorg.github.io/guideline/5.3.0.RELEASE/en/Security/OAuth.html)
![work flow](https://user-images.githubusercontent.com/19374409/56719370-2b7ca600-6773-11e9-83d9-efc387cf373b.png)
1. User_Agent 访问 Client
>用户 user agent 访问客户端 client，client 通过 Service 调用 OAuth2RestTemplate，由于没有授权，client 让 user agent 重定向到 Authorization Server 的 Authorization Endpoint

2. User Agent 访问 Authorization Server 的 AuthorizationEndPoint
>用户 user agent 访问AuthorizationEndpoint ， AuthorizationEndpoint 页面展示出需要 Resource Owner 进行同意授权，如果同意则 AuthorizationEndpoint 产生授权码 authorization code，authorization code 通过 user agent 返回给 client

3. Client 访问 Authorization Server 的 TokenEndPoint
>Client 通过 OAuth2RestTemplate 访问 Authorization Server 的 TokenEndPoint，TokenEndpoint 校验 authorization code ，校验通过后调用 AuthorizationServerTokenService 产生 token

4. Client 访问 Resource Server
>client 通过 OAuth2RestTemplate 附带 token访问resource server，Resource server 调用OAuth2AuthenticationManager 通过 ResourceServerTokenServices 校验 token 信息，校验通过则返回资源给 client

其中的 End point，已经通过Spring 的注解 @FrameworkEndpoint 实现了
token产生时，client 的相关信息通过 ClientDetailsService 注册到了 Authorization Server

#### 创建客户端信息表
```
create table if not exists oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);
```

| 列名 | 类型 | 描述 |
| ---- | ---- | ---- |
| client_id（主键）	| VARCHAR(256)	| 主键,必须唯一,不能为空. 用于唯一标识每一个客户端(client); 在注册时必须填写(也可由服务端自动生成). 对于不同的grant_type,该字段都是必须的。在实际应用中的另一个名称叫appKey,与client_id是同一个概念 |
| resource_ids | VARCHAR(256) |	客户端所能访问的资源id集合,多个资源时用逗号(,)分隔 |
| client_secret	| VARCHAR(256)	| 用于指定客户端(client)的访问密匙; 在注册时必须填写(也可由服务端自动生成). 对于不同的grant_type,该字段都是必须的. 在实际应用中的另一个名称叫appSecret,与client_secret是同一个概念 |
| scope	| VARCHAR(256)	| 指定客户端申请的权限范围,可选值包括read,write,trust;若有多个权限范围用逗号(,)分隔,如: “read,write” |
| authorized_grant_types	| VARCHAR(256)	| 指定客户端支持的grant_type,可选值包括authorization_code,password,refresh_token,implicit,client_credentials,若支持多个grant_type用逗号(,)分隔,如: “authorization_code,password”在实际应用中,当注册时,该字段是一般由服务器端指定的,而不是由申请者去选择的 |
| web_server_redirect_uri	| VARCHAR(256)	| 客户端的重定向URI,可为空, 当grant_type为authorization_code或implicit时, 在Oauth的流程中会使用并检查与注册时填写的redirect_uri是否一致 |
| authorities	| VARCHAR(256)	| 指定客户端所拥有的Spring Security的权限值,可选, 若有多个权限值,用逗号(,)分隔, 如: "ROLE_ADMIN" |
| access_token_validity	| INTEGER	| 设定客户端的access_token的有效时间值(单位:秒),可选, 若不设定值则使用默认的有效时间值(60 * 60 * 12, 12小时) |
| refresh_token_validity	| INTEGER	| 设定客户端的refresh_token的有效时间值(单位:秒),可选, 若不设定值则使用默认的有效时间值(60 * 60 * 12, 12小时) |
| additional_information	| VARCHAR(4096)	| 这是一个预留的字段,在Oauth的流程中没有实际的使用,可选,但若设置值,必须是JSON格式的数据,在实际应用中, 可以用该字段来存储关于客户端的一些其他信息 |
| autoapprove	| VARCHAR(256)	| 设置用户是否自动Approval操作, 默认值为 ‘false’, 可选值包括 ‘true’,‘false’, ‘read’,‘write’该字段只适用于grant_type="authorization_code"的情况,当用户登录成功后,若该值为’true’或支持的scope值,则会跳过用户Approve的页面,直接授权 |
#### 获取授权码
mysql 表 oauth_client_details 中添加一条客户端记录

| client_id | resource_ids | client_secret | scope | authorized_grant_types | web_server_redirect_uri |
| ---- | ---- | ---- | ---- | ---- | ---- |
| oauth2	| resource	| $2a$10$Cf.ui70XRGI.xUDM24xuLOCH0n/Xz7s6hsL1U0DSjpets913KTym.	| all	| authorization_code,password |	http://example.com |

访问获取授权码
>http://localhost:8000/oauth/authorize?response_type=code&client_id=oauth2&redirect_uri=http://example.com&scope=all 


#### spring-security-oauth2-autoconfigure
pom.xml 中的 spring-security-oauth2-autoconfigure 是自动配置的包，通过陪配置文件就可以完成一个授权服务器和资源服务器，
如果自定义授权服务器就是配置属于我们自己的 AuthorizationServerConfigurer了，当 spring 扫描到我们实现的配置以后，就不
回去自动配置 oauth2 了

#### 自定义授权服务器
spring 提供了相应的适配器 AuthorizationServerConfigurerAdapter 类来供我们实现 AuthorizationServerConfigurer 这个接口，
我们只要继承这个类，可选择的 override 其中的三个方法
```
// 配置授权服务器的安全信息，比如 ssl 配置、checktoken 是否允许访问，是否允许客户端的表单身份验证等
public void configure(AuthorizationServerSecurityConfigurer security) {  }
// 配置客户端的 service，就是应用怎么获取到客户端的信息，一般来说是从内存或者数据库中获取
public void configure(ClientDetailsServiceConfigurer clients) {  }
// 配置授权服务器各个端点的非安全功能，如令牌存储，令牌自定义，用户批准和授权类型
// (如果需要密码授权模式，需要提供 AuthenticationManager 的 bean)
public void configure(AuthorizationServerEndpointsConfigurer endpoints) {}
```
>new BCryptPasswordEncoder().encode("oauth2") 每次加密的结果不一样

#### 注解RequiredArgsConstructor
来源于lombok.RequiredArgsConstructor;使用类中所有带有@NonNull注解的或者带有final修饰的成员变量生成对应的构造方法
```Java
@Configuration
@RequiredArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    // 数据源
    private final @NonNull DataSource dataSource;

    @Bean
    public ClientDetailsService clientDetails() {
        return new JdbcClientDetailsService(dataSource);
    }
}    
```
也可以使用 AutoWired 自动注入
```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    // 数据源
    @Autowired
    private final  DataSource dataSource;

    @Bean
    public ClientDetailsService clientDetails() {
        return new JdbcClientDetailsService(dataSource);
    }
} 
```
#### JWT
JSON Web Token（JWT）是一套开放的标准安全地在客户端和服务器之间传输 JSON 格式的信息
JWT的构成，由三部分以分隔符"."连接构成
>1. header (声明类型和加密算法)
>1.1. 声明类型
>1.2. 声明加密算法
>2. payload (载荷就是存放有效信息)
>3. signature
>3.1 header (base64后的)
>3.2 payload (base64后的)
>3.3 secret

header 如下，再对其进行 base64加密就是 JWT 的第一部分
```
{
  'typ': 'JWT',
  'alg': 'HS256'
}
```
payload 包括三个部分，再对其进行base64加密就是 JWT 的第二部分
1标准中注册的声明
2公共的声明
3私有的声明

```
/ javascript
var encodedString = base64UrlEncode(header) + '.' + base64UrlEncode(payload);

var signature = HMACSHA256(encodedString, 'secret'); 
```
signature 这个部分需要base64加密后的header和base64加密后的payload使用"."连接组成的字符串，
然后通过header中声明的加密方式进行加盐 secret 组合加密，然后就构成了 JWT 的第三部分

如何应用
一般是在请求头里加入Authorization，并加上Bearer标注
```
fetch('api/user/1', {
  headers: {
    'Authorization': 'Bearer ' + token
  }
})
```
#### JWT 加密方式
signature 对 base64 加密后的 header 和 base64 加密后的 payload 使用"."连接组成的字符串加密就涉及到两种加密方式：
>1. 对称加密(么钥加密)
>2. 非对称加密(公钥加密)

对称加密,又称私钥加密，即信息的发送方和接收方用一个密钥去加密和解密数据。
最大优势是加/解密速度快，适合于对大数据量进行加密，对称加密的一大缺点是密钥的管理与分配
现实中通常的做法是将对称加密的密钥进行非对称加密，然后传送给需要它的人。而在 spring security 之中的相应的
实现类是 org.springframework.security.jwt.crypto.sign.MacSigner
```
Signer  jwtSigner = new MacSigner("hand");//默认HMACSHA256 算法加密
Signer  jwtSigner = new MacSigner("HMACSHA256","hand");//手动设置算法
```

非对称加密,它使用了一对密钥，公钥（public key）和私钥（private key）。私钥只能由一方安全保管，不能外泄，
而公钥则可以发给任何请求它的人。非对称加密使用这对密钥中的一个进行加密，而解密则需要另一个密钥。
在 spring security 之中的相应实现是 org.springframework.security.jwt.crypto.sign.RsaSigner
```
KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("mytool.jks"), "mypass".toCharArray());
KeyPair demo = keyStoreKeyFactory.getKeyPair("mytool");
Signer jwtSigner = new RsaSigner((RSAPrivateKey)demo.getPrivate());
```
#### 对称密钥生成 jwt 令牌
生成 jwt 格式的 token 步骤
>1. 创建令牌转换器(作用是 JWT 编码的令牌和 OAuth 身份验证信息之间进行转换)
>2. 创建 JwtTokenStore
>3. 配置进 AuthorizationServerEndpointsConfigurer

```
@Override
public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
    // 3. 配置进 AuthorizationServerEndpointsConfigurer
    endpoints.authenticationManager(this.authenticationManager)
        .tokenStore(tokenStore())
        .accessTokenConverter(jwtAccessTokenConverter());
}

/**
 * 1. 令牌转换器，对称密钥加密
 *
 * @return JwtAccessTokenConverter
 */
@Bean
public JwtAccessTokenConverter jwtAccessTokenConverter() {
    JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
    converter.setSigningKey("oauth2");
    return converter;
}

/**
 * 2. token store 实现
 *
 * @return JwtTokenStore
 */
@Bean
public TokenStore tokenStore() {
    return new JwtTokenStore(jwtAccessTokenConverter());
}
```
#### 非对称密钥生成 jwt 令牌
生成 jwt 格式的 token 步骤
>生成密钥对
>创建令牌转换器
>创建 JwtTokenStore
>配置进 AuthorizationServerEndpointsConfigurer

首先利用 keytool 进行密钥对的生成，在目录 C:\Program Files\Java\jdk1.8.0_101\bin 内执行如下命令
```
keytool -genkey -alias oauth2 -keyalg RSA -keystore D:\Mobile_Erp\spring-security-oauth2-jwt\rsaSigner-mysql\src\main\resources\oauth2.jks -keysize 2048
```
生成公钥
```
keytool -list -rfc --keystore D:\Mobile_Erp\spring-security-oauth2-jwt\rsaSigner-mysql\src\main\resources\oauth2.jks | C:\OpenSSL-Win64\bin\openssl x509 -inform pem -pubkey
```

温馨提示：生成密钥对需要安装 jdk 和 openssl
openssl windows edition download [here](http://slproweb.com/products/Win32OpenSSL.html)
openssl linux edition download [here](https://www.openssl.org/source/ )
```
  @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore())
                .accessTokenConverter(jwtAccessTokenConverter());
    }

    /**
     * 1. 令牌转换器，对称密钥加密
     *
     * @return JwtAccessTokenConverter
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();    
        //****** 非对称加密  Begin *********
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                new ClassPathResource("oauth2.jks"), "123456".toCharArray());
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("oauth2"));
        //****** 非对称加密  Begin *********
        return converter;
    }

    /**
     * 2. token store 实现
     *
     * @return JwtTokenStore
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }
```
#### 令牌增强器(为 jwt 添加更多的信息)
需要一个类来实现 TokenEnhancer 接口，分以下几步
>1. 实现 TokenEnhancer 接口
>2. 使用一个复合令牌增强器 TokenEnhancerChain，循环遍历将其委托给增强器。
>3. 配置进 AuthorizationServerEndpointsConfigurer
```Java
@Component
public class InfoTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        // 创建一个自定义信息
        Map<String, Object> additionalInfo = new HashMap<>(1);
        // 设置值
        additionalInfo.put("organization", authentication.getName());
        // 存进去
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        // 返回
        return accessToken;
    }
}

````
复合令牌增强器 TokenEnhancerChain，循环遍历将其委托给增强器
```
@Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    //  3 复合令牌增强器 TokenEnhancerChain，循环遍历将其委托给增强器
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers( Arrays.asList(tokenEnhancer, jwtAccessTokenConverter()));
// 4 配置进 AuthorizationServerEndpointsConfigurer
        endpoints.tokenStore(tokenStore())
                .tokenEnhancer(tokenEnhancerChain);

    }


    /**
     * 1. 令牌转换器，对称密钥加密
     *
     * @return JwtAccessTokenConverter
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        //****** 非对称加密  Begin *********
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                new ClassPathResource("oauth2.jks"), "123456".toCharArray());
         //  这里的 getKeyPair 内容为生成密钥对时指定的 alias 名
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("oauth2"));
        //****** 非对称加密  Begin *********
        return converter;
    }

    /**
     * 2. token store 实现
     *
     * @return JwtTokenStore
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }
```
从 jwt [网站](www.jwt.io)，粘贴上公钥后可以解析出JWT 明文内容
#### check_token 端点的开放
资源服务器就能够向授权服务器验证并解析 token 获取用户信息(能够验证和解析 token)
```
@Override
public void configure(AuthorizationServerSecurityConfigurer security) {
    security
        .checkTokenAccess("isAuthenticated()");
}
```

#### 授权码模式登录页面的自定义
授权码模式登录页面的自定义和 spring security 配置自定义登录页面是一样
登录请求地址 /authorization/form
自定义表单登录(此处使用静态页面方式，还可以使用模版引擎)，分为两步完成：
>1. 配置路径与请求
>2. 填充页面与修改

spring security web 安全配置的 SecurityConfig 类中
```
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
        // 登录页面名称，他会去寻找 resources 下的 resources 和 static 目录
        .loginPage("/login.html")
        // 登录表单提交的路径
        .loginProcessingUrl("/authorization/form")
        .and()
        // 关闭 csrf 防护，因为对于我们的所有请求来说，都是需要携带身份信息的
        .csrf().disable();
}
```
关闭 csrf 防护，有效防护 csrf 的一种方式是 在请求地址中添加 token 并验证
login.html内容如下
```
<form class="login100-form validate-form" action="/authorization/form" method="post">
                <span class="login100-form-title p-b-49">登录static 下</span>

                <div class="wrap-input100 validate-input m-b-23" data-validate="请输入用户名">
                    <label class="label-input100" for="username">用户名</label>
                    <input class="input100" type="text" id="username" name="username" placeholder="请输入用户名" autocomplete="off">
                </div>

                <div class="wrap-input100 validate-input" data-validate="请输入密码">
                    <label class="label-input100" for="password">密码</label>
                    <input class="input100" type="password" id="password" name="password" placeholder="请输入密码">
                </div>

                <div class="container-login100-form-btn">
                    <div class="wrap-login100-form-btn">
                        <div class="login100-form-bgbtn"></div>
                        <button type="submit" class="login100-form-btn">登 录</button>
                    </div>
                </div>  
</form>
```
basic 对话框登录方式，只需要配置如下即可
```
@Override
protected void configure(HttpSecurity http) throws Exception {
	http.httpBasic();
}
```

自定义表单登录(此处使用模版引擎方式，还可以使用静态页面)
配置类 SecurityProperties，读取配置文件application.yml中设定的模版文件中引用的变量
```
protected void configure(HttpSecurity http) throws Exception {
        
        // ******************************************  表单静态页面方式  Begin **********************
        http.formLogin()
                // 登录页面名称，他会去寻找 resources 下的 resources 和 static 目录
                .loginPage("/login.html")   //  login.html 位于 static 子目录
                // 登录表单提交的路径
                .loginProcessingUrl("/authorization/form")
                .and()
                // 关闭 csrf 防护，因为对于我们的所有请求来说，都是需要携带身份信息的
                .csrf().disable();
        // ****************************************** 表单静态页面方式 End **********************



        // ****************************************** 表单模版引擎方式 Begin **********************
        http.formLogin()
                .loginPage("/oauth/login")  // 控制器中可自定义跳转 ViewName
                .loginProcessingUrl(securityProperties.getLoginProcessingUrl());


        // ****************************************** 表单模版引擎方式 End **********************

    }
```
自定义登录模版引擎页面 Controller
```Java
@Controller
@RequestMapping("/oauth")
public class OauthController {
    @Autowired
    private SecurityProperties securityProperties;

    @GetMapping("/login")
    public String loginView(Model model){
        model.addAttribute("action",securityProperties.getLoginProcessingUrl()); // 从配置文件中读取
        return "form-login";
    }
}
```
form-login.html内容如下
```
<form class="login100-form validate-form" th:action="${action}" method="post">
                <span class="login100-form-title p-b-49">登录templates下</span>

                <div class="wrap-input100 validate-input m-b-23" data-validate="请输入用户名">
                    <label class="label-input100" for="username">用户名</label>
                    <input class="input100" type="text" id="username" name="username" placeholder="请输入用户名" autocomplete="off">
                </div>

                <div class="wrap-input100 validate-input" data-validate="请输入密码">
                    <label class="label-input100" for="password">密码</label>
                    <input class="input100" type="password" id="password" name="password" placeholder="请输入密码">
                </div>

                <div class="container-login100-form-btn">
                    <div class="wrap-login100-form-btn">
                        <div class="login100-form-bgbtn"></div>
                        <button type="submit" class="login100-form-btn">登 录</button>
                    </div>
                </div>
 
            </form>
```
SecurityProperties.java 从 application.yml 中读取
```Java
@Data
@Configuration
@ConfigurationProperties("application.security.oauth")
public class SecurityProperties {

    /**
     * 登录请求的路径，默认值 /authorization/form
     */
    private String loginProcessingUrl = "/authorization/form";

}
```
#### 自定义授权页面
默认授权请求地址 /oauth/confirm_access
Controller 控制器如下
```Java
@Controller
@SessionAttributes("authorizationRequest")  // 重要！
public class AuthorizationController {
    @RequestMapping("/oauth/confirm_access")
    public ModelAndView getAccessConfirmation(Map<String, Object> model, HttpServletRequest request) throws Exception {
        AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
        ModelAndView view = new ModelAndView();
        view.setViewName("authorization");
        view.addObject("clientId", authorizationRequest.getClientId());
        view.addObject("scopes",authorizationRequest.getScope());
        view.addObject("scopeName",String.join(",",authorizationRequest.getScope()));
        return view;
    }
}
```
authorization.html 如下
```
<form class="login100-form validate-form" action="/oauth/authorize" method="post">
                <span class="login100-form-title p-b-49"
                      th:text="${clientId} + ' 请求授权，该应用将访问您的资源信息。将会取得如下权限：' + ${scopeName}">
                    请求授权
                </span>
                <div class="wrap-input100 validate-input m-b-23">
                    <input type="hidden" name="user_oauth_approval" value="true">
                    <div style="display: none" th:each="scope : ${scopes}">
                        <input type="hidden" th:name="'scope.' + ${scope}" value="true">
                    </div>
                    <input type="hidden" name="_csrf" th:value="${_csrf.token}"/>
                </div>

                <div class="container-login100-form-btn">
                    <div class="wrap-login100-form-btn">
                        <div class="login100-form-bgbtn"></div>
                        <button type="submit" class="login100-form-btn">确认授权</button>
                    </div>
                </div>

            </form>
```
#### 资源服务器
资源服务器的关键接口为 ResourceServerConfigurer，它的适配器为 ResourceServerConfigurerAdapter，
只需要继承他的适配器即可，他有如下两个方法：

|方法名	|参数类型	|描述|
| ---|---|---|
|configure	|ResourceServerSecurityConfigurer	|资源服务器的属性配置，默认值应该适用于许多应用程序，但可能至少要更改资源ID。|
|configure	|HttpSecurity	|使用此项配置安全资源的访问规则。默认情况下，不在 “/oauth/**” 中的所有资源是受保护的。这个其实就是和 ``spring security` 的配置方式是一样的。|

资源服务器，提供了两种验证与解析令牌的方式

|解析方式	|实现类|	优点|	缺点|
| --- | ---| ---| --- |
|本地解析|	DefaultTokenServices|	解析快速，不需要发送任何请求，可以配置令牌存储等。|	一旦授权服务器令牌解析方式发生调整，本地也要进行调整。向资源服务器/客户端提供令牌解析方式是极其不安全的行为。|
|远程解析|	RemoteTokenServices|	资源服务器配置大大减少，方便快捷，自适应授权服务器变化。|	受网络的影响，一旦两个服务器不再一个局域网内，效率会大大降低。|

```Java
@Configuration
@EnableResourceServer
public class Oauth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        // 设置资源服务器的 id
        resources.resourceId("oauth2");
    }

}
```
1. 普通加密方式
配置文件 application.yml ，分别指定了如下参数：

>资源服务器的启动端口在 9000
资源服务器检查token和解析用户信息的路径在 http://localhost:8000/oauth/check_token
客户端获取令牌的位置 http://localhost:8000/oauth/token
客户端信息
```
server:
  port: 9000

security:
  security:
    resource:
      token-info-uri: http://localhost:8000/oauth/check_token
    client:
      access-token-uri: http://localhost:8000/oauth/token
      client-id: oauth2
      client-secret: oauth2 # 这里必须是加密前的密钥
      grant-type: authorization_code,password,refresh_token
      scope: all
```
客户端令牌的读取不管是从 配置文件application.yml还是数据库都需要在配置文件中指定
资源服务器向授权服务器验证并解析 token 获取用户信息的端点 /oauth/check_token
>security.security.resource.token-info-uri=http://localhost:8000/oauth/check_token

2. jwt加密
jwt对称加密方式 
Begin
授权服务器 Oauth2AuthorizationServerConfig 设置
```
/**
     * 1. 令牌转换器，对称密钥加密
     *
     * @return JwtAccessTokenConverter
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        //***** 对称加密  Begin *********
        setSigningKey 方法中的 isPublic 方法已经判断是否使用对称 or 非对称方法
        converter.setSigningKey("oauth2");
        //***** 对称加密  End *********

        //****** 非对称加密  Begin *********
      //  KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("oauth2.jks"), "your_pwd".toCharArray());
         //  这里的 getKeyPair 内容为生成密钥对时指定的 alias 名
       // converter.setKeyPair(keyStoreKeyFactory.getKeyPair("oauth2"));
        //****** 非对称加密  End *********

        return converter;
    }
```
资源服务器 Ouath2ResourceServerConfig 设置
自动配置
```
@Configuration
@EnableResourceServer
public class Ouath2ResourceServerConfig extends ResourceServerConfigurerAdapter{

    @Autowired
    private ResourceServerProperties resourceServerProperties;
    
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception{
        resources.resourceId(resourceServerProperties.getResourceId());
    }
```
application.yml
```
security:
  oauth2:
    resource:
      token-info-uri: http://localhost:8000/oauth/check_token
      id: resourceOne
      jwt:
        key-uri: http://localhost:8000/oauth/token_key
        key-value: oauth2
        
    client:
      access-token-uri: http://localhost:8000/oauth/token
      client-id: oauth2
      client-secret: oauth2
      grant-type: authorization_code,password,refresh_token
      scope: all
```
手动配置(ignore)
End
jwt非对称加密方式
授权服务器 Oauth2AuthorizationServerConfig 设置
```
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        //***** 对称加密  Begin *********
       // setSigningKey 方法中的 isPublic 方法已经判断是否使用对称 or 非对称方法
       // converter.setSigningKey("oauth2");
        //***** 对称加密  End *********

        //****** 非对称加密  Begin *********
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("oauth2.jks"), "your_pwd".toCharArray());
         //  这里的 getKeyPair 内容为生成密钥对时指定的 alias 名
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("oauth2"));
        //****** 非对称加密  End *********

        return converter;
    }
``` 
资源服务器 Ouath2ResourceServerConfig 设置
自动配置方式
```
@Autowired
    private ResourceServerProperties resourceServerProperties;
    
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception{
        resources.resourceId(resourceServerProperties.getResourceId());
    }
```
application.yml
```
security:
  oauth2:
    resource:
      token-info-uri: http://localhost:8000/oauth/check_token
      id: resourceOne
      jwt:
        key-uri: http://localhost:8000/oauth/token_key
        key-value: |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArgNO1Gp7I48dz+Dp5/sO
          EF53BjQ/X6o4wvTzmVaENchHiHPr9IfPsMR/qMloC1U60XUUKdhmbCKORqBLFJDt
          u4F4QMq/h/oymMLkRIa+dnj2QEvSj4xcgVuvwH4f4AHr71AaJyW1zu7Z7AH20JQk
          U5QZ+zCLd8WnT17sxMYgfGThkLq3xGOiXjGY0qAtN4KWhwJEAMIATiw/akLQL+p/
          iQMHwiaoNRvcas9C0hA4FYfcjoEobwu07bDZmM2Dl3eP/pCdFPMjyyMKM9zwfq0o
          MxLmxGSMQQdCz0hBio8IUkGzKAAtkdFPu8S5zx3+n4rCzYGN0/pw3KSrRFNTf3om
          lwIDAQAB
          -----END PUBLIC KEY-----

    client:
      access-token-uri: http://localhost:8000/oauth/token
      client-id: oauth2
      client-secret: oauth2
      grant-type: authorization_code,password,refresh_token
      scope: all
```
手动配置方式
```
@Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception{
        // 设置资源服务器的 id
        resources.resourceId(resourceServerProperties.getResourceId());
        resources.tokenServices(tokenServices());
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setVerifierKey(getPubKey());
        return converter;
    }


    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        return defaultTokenServices;
    }

    private String getPubKey() {
        return StringUtils.isEmpty(resourceServerProperties.getJwt().getKeyValue())
                ? getKeyFromAuthorizationServer()
                : resourceServerProperties.getJwt().getKeyValue();
    }

    private String getKeyFromAuthorizationServer() {
        ObjectMapper objectMapper = new ObjectMapper();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization", encodeClient());
        HttpEntity<String> requestEntity = new HttpEntity<>(null, httpHeaders);
        String pubKey = new RestTemplate()
                .getForObject(resourceServerProperties.getJwt().getKeyUri(), String.class, requestEntity);
        try {
            Map map = objectMapper.readValue(pubKey, Map.class);
            System.out.println("联网公钥");
            return map.get("value").toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private String encodeClient() {
        return "Basic " + Base64.getEncoder().encodeToString((resourceServerProperties.getClientId()
                + ":" + resourceServerProperties.getClientSecret()).getBytes());
    }
```

#### session 存储在 redis 中
session存到redis并不是用字符串类型来存，它存储的格式是 hash
配置文件中设置 spring.session.store-type=redis 或者 @EnableRedisHttpSession 注解
```
spring:session:sessions:db031986-8ecc-48d6-b471-b137a3ed6bc4
spring:session:expirations:1472976480000
```
1. 其中 1472976480000为失效时间，意思是这个时间后session失效
2. db031986-8ecc-48d6-b471-b137a3ed6bc4 为sessionId
3. spring:session是spring session在redis里面的命名空间，默认就是“spring:session"，在org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration的源代码里面可以看到

配置文件格式设置 client 格式
```
security:
  oauth2:
    client:
      registered-redirect-uri: http://example.com
      # 客户端 id
      client-id: oauth
      client-secret: oauth
      scope: all
      access-token-validity-seconds: 600
      refresh-token-validity-seconds: 600
      grant-type: authorization_code,password
      # 可以访问的资源
      resource-ids: oauth2
    authorization:
      # 允许使用 /oauth/check_token 端点
      check-token-access: isAuthenticated()
    resource:
      id: oauth2
````
AbstractRedirectResourceDetails.java 中 Line 44中获取 客户端传过来的 redirect_uri

>oauth_client_details表中获取client信息时字段additional_information为空不为NULL报错

JdbcClientDetailsService.java类 Line 268 在从数据库加载 clients 信息时，字段 additional_information 
内容为空而不为NULL时报错，参考[花儿为什么这么红](https://www.cnblogs.com/chancy/p/11635513.html)

```
JdbcClientDetailsService :Could not decode JSON for additional information: BaseClientDetails
java.io.EOFException: No content to map to Object due to end of input
```
解决方法 additional_information 内容填写为 NULL 或者 json 字符串


### SSO登出
[废物大师兄 ](https://www.cnblogs.com/cjsblog/p/10548022.html)介绍的SSO案例多 client登录可行，但没有实现登出功能

>调用认证中心的 logout 方法出错

clientOne 调用登出HttpSecurity.logout().logoutSuccessUrl("http://localhost:8000/logout") 
成功后再调用server的logout，如果不添加没 http.csrf().disable(); 登出会失败，可能是因为不加这个将只支持post方式的logout退出

在[baeldung](https://www.baeldung.com/spring-security-oauth-revoke-tokens)中介绍的有通过刷新 token 使得原来颁发的
标准 token 失效，但不适用于 jwt
```
this article only covers the standard token implementation in the framework, not JWT tokens
```
jwt 无法使全部client logout,原因在[这里](https://stackoverflow.com/questions/46150345/spring-boot-oauth-2-server-with-jwt-token-logout)
```
JWT token is self-contained, which means that all information regarding the authentication are in the token itself. If you want to check, 
if a user is logged in, you just need to check the signature in the JWT token and the token expiration time. No communication with a server is required.

If you want to logout a user with JWT token, you need to delete the JWT token on the client side. And preferrably, the expiration time of JWT 
tokens should be rather short and the client should e.g. use refresh tokens to get new tokens
```

maven plugin 设置
<!--创建一个自动可执行的jar或war文件 -->
```
<plugin>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-maven-plugin</artifactId>
      <version>2.2.1.RELEASE</version>
      <executions>
        <execution>
          <goals>
            <goal>repackage</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
```

热部署依赖
```

```
以下配置则不会在代码更改时热启动，只有静态文件更改时刷新浏览器就可以生效
Devtools can also be configured to only refresh the browser whenever a static resource has changed (and ignore any change in the code)
>spring.devtools.remote.restart.enabled=false

或者这样设置
```
<plugin>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-maven-plugin</artifactId>
      <version>2.2.1.RELEASE</version>
      <configuration>
        <addResources>true</addResources>
      </configuration>
    </plugin>
```
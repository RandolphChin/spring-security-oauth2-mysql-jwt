package cn.randy.config;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.util.Arrays;

@Configuration
@RequiredArgsConstructor  // 生成一个包含常量或标识了NonNull的变量的私有构造方法
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    // 数据源
    private final @NonNull DataSource dataSource;

    private  @NonNull InfoTokenEnhancer tokenEnhancer;

    // authorizatin_type 为 password 时需要
    private @NonNull AuthenticationManager authenticationManager;
    // 使用 oauth/refresh_token 端点api 时需要手动注入到授权服务器安全中
    private @NonNull UserDetailsService userDetailsService;

    /**
     * 声明 ClientDetails实现，从数据库读取 Client 信息
     * @return ClientDetailsService
     */
    @Bean
    public ClientDetailsService clientDetails() {
        return new JdbcClientDetailsService(dataSource);
    }

    /**
     * 配置客户端的 service，就是应用怎么获取到客户端的信息，一般来说是从内存或者数据库中获取
     *   ClientDetailsService 配置进 ClientDetailsServiceConfigurer 之中
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetails());
    }

    /**
     * 配置授权服务器各个端点的非安全功能，如令牌存储，令牌自定义，用户批准和授权类型
     * 使用 oauth/refresh_token 端点api 时userDetailsService需要手动注入到授权服务器安全中
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers( Arrays.asList(tokenEnhancer, jwtAccessTokenConverter()));

        endpoints.tokenStore(tokenStore())
                .tokenEnhancer(tokenEnhancerChain)
                .userDetailsService(userDetailsService)
               .authenticationManager(authenticationManager);
    }

/*
  *  token store 实现
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }
*/

    /**
     * 1. 令牌转换器，对称密钥加密
     *
     * @return JwtAccessTokenConverter
     */
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

    /**
     * 2. token store 实现
     *
     * @return JwtTokenStore
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 配置授权服务器的安全信息，比如 ssl 配置、checktoken 是否允许访问，是否允许客户端的表单身份验证等
     * @param security
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security // 资源服务器就能够向授权服务器验证并解析 token 获取用户信息(授权服务器添加 check_token 端点支持。)
                .checkTokenAccess("isAuthenticated()");
        security // 允许资源服务器能够访问公钥端点 oauth/token_key
                .tokenKeyAccess("isAuthenticated()");
        // allowFormAuthenticationForClients允许client在页面使用form的方式进行authentication的授权
        // security.allowFormAuthenticationForClients();
    }
}

package cn.randy.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties("application.security.oauth")
public class SecurityProperties {

    /**
     * 登录请求的路径，如果配置文件中没有 application.security.oauth.loginProcessingUrl 则默认为该值 /authorization/form
     */
    private String loginProcessingUrl = "/authorization/form";

}
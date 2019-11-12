package cn.randy.config;

import cn.randy.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 *  配置 spring security web 安全
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailsService userDetailsService;

    // 从数据库存用户信息
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    // 不加这个也不影响，不会拦截静态资源
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/assets/**", "/css/**", "/images/**","/fonts/**","/js/**","/vendor/**");
    }

    /**
     *   Spring 5 之后必须对密码进行加密
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }

    /**
     * @return 数据库查询用户令牌
     */
       /*
            * InMemoryUserDetailsManager 创建两个内存用户
     * 用户名 user 密码 123456 角色 ROLE_USER
     * 用户名 admin 密码 admin 角色 ROLE_ADMIN
     **/
       /*
    @Bean
    protected UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manage = new InMemoryUserDetailsManager();
        manage.createUser(User.withUsername("user")
                        .password(passwordEncoder().encode("123456"))
                        .authorities("ROLE_USER").build() );
        manage.createUser(User.withUsername("admin")
                .password(passwordEncoder().encode("admin"))
                .authorities("ROLE_ADMIN").build() );
        return manage;
    }
        */


    @Autowired
    private SecurityProperties securityProperties;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ******************************************  http basic 对话框方式 Begin ***********************
         // http.httpBasic();
        // ******************************************  http basic 对话框方式 End ***********************

        /*
        // ******************************************  表单静态页面方式  Begin **********************
        http.formLogin()
                // 登录页面名称，他会去寻找 resources 下的 resources 和 static 目录
                .loginPage("/login.html")
                // 登录表单提交的路径
                .loginProcessingUrl("/authorization/form")
                .and()
                // 关闭 csrf 防护，因为对于我们的所有请求来说，都是需要携带身份信息的
                .csrf().disable();
        // ****************************************** 表单静态页面方式 End **********************
*/


        // ****************************************** 表单模版引擎方式 Begin **********************
        // 这里需要注意 logoutSuccessURL失败的可能原因，是因为没有添加 http.csrf().disable(); 不加这个将只支持post方式的logout退出
        http.
                authorizeRequests()
                .antMatchers("/login", "/oauth/**").permitAll()
                .and()
                .formLogin()
                .loginPage("/oauth/login")
                .loginProcessingUrl(securityProperties.getLoginProcessingUrl())
                .and()
                .csrf().disable();


        // ****************************************** 表单模版引擎方式 End **********************

        // 这里需要注意 开启了 csrf 防护 授权界面的 <input type="hidden" name="_csrf" th:value="${_csrf.token}"/> 是必须要添加的
        // 如果关闭了 csrf 防护，这个 <input type="hidden" name="_csrf" th:value="${_csrf.token}"/> 不需要添加

    }

    // authorizatin_type 为 password 时需要
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


}
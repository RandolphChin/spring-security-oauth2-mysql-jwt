package cn.randy.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Spring Security默认是禁用注解的，要想开启注解，需要在继承WebSecurityConfigurerAdapter的类上
 * 加@EnableGlobalMethodSecurity注解，来判断用户对某个控制层的方法是否具有访问权限
 */

@EnableOAuth2Sso
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    //**************************此种方式只能 logout 一个 client ***** Begin *********************

        http.logout().logoutSuccessUrl("http://localhost:8000/logout")
                .and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .csrf().disable();

    //**************************此种方式只能 logout 一个 client ******* End ******************

     //**************************此种方式也只能 logout 一个 client ***** Begin *********************
      /*
        http
                .logout()
                .logoutSuccessUrl("http://localhost:8000/oauth/exit")
                .and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .csrf().disable();
        */
    //**************************此种方式不能只能 logout 一个 client ******* End ******************
    }
}


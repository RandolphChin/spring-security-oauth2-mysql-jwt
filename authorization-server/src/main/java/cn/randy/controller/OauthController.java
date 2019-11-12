package cn.randy.controller;


import cn.randy.config.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 模版引擎方式引导至自定义登录界面 /oauth/login 在 spring security中定义
 */
@Controller
@RequestMapping("/oauth")
public class OauthController {
    @Autowired
    private SecurityProperties securityProperties;

    @GetMapping("/login")
    public String loginView(Model model){
        model.addAttribute("action",securityProperties.getLoginProcessingUrl());
        return "form-login";
    }

    /**
     *  自定义 登出 logout 方法，和 HttpSecurity.logout().logoutSuccessUrl("http://localhost:8000/logout") 效果一样
     *  只能 logout 一个 client 不能 logout 所有的
     * @param request
     * @param response
     */
    @RequestMapping("/exit")
    public void exit(HttpServletRequest request, HttpServletResponse response) {
        // token can be revoked here if needed
        new SecurityContextLogoutHandler().logout(request, null, null);
        try {
            //sending back to client app
            System.out.println(request.getHeader("referer"));
            response.sendRedirect(request.getHeader("referer"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

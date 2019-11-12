package cn.randy.controller;

import jdk.nashorn.internal.objects.annotations.Getter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

@Controller
public class ClientTwoController {
    @GetMapping("/list")
    public String list(HttpServletRequest request){
        Cookie[]  cookies = request.getCookies();
        if(cookies == null || cookies.length <= 0){
            return null;
        }
        for(Cookie cookie : cookies) {
            System.out.println("from client two: "+cookie.getName() + " --- "+cookie.getValue());
        }
        return "index";
    }
}

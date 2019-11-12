package cn.randy.service;


import cn.randy.entity.SysUser;

public interface MyUserService {
    SysUser getByUsername(String username);
}

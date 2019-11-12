package cn.randy.service.impl;

import cn.randy.entity.SysUser;
import cn.randy.repository.SysUserRepository;
import cn.randy.service.MyUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MyUserServiceImpl implements MyUserService {

    @Autowired
    private SysUserRepository sysUserRepository;

    @Override
    public SysUser getByUsername(String username) {
        return sysUserRepository.findByUsername(username);
    }
}

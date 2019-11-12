package cn.randy.service;

import cn.randy.domain.MyUser;
import cn.randy.entity.SysPermission;
import cn.randy.entity.SysUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MyUserService myUserService;

    @Autowired
    private MyPermissionService permissionService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser sysUser = myUserService.getByUsername(username);
        if (null == sysUser) {
            throw new UsernameNotFoundException(username);
        }
        List<SysPermission> permissionList = permissionService.findByUserId(sysUser.getId());
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        if (!CollectionUtils.isEmpty(permissionList)) {
            for (SysPermission sysPermission : permissionList) {
                authorityList.add(new SimpleGrantedAuthority(sysPermission.getCode()));
            }
        }

        MyUser myUser = new MyUser(sysUser.getUsername(), passwordEncoder.encode(sysUser.getPassword()), authorityList);
        myUser.setId(sysUser.getId());

        return myUser;
    }
}

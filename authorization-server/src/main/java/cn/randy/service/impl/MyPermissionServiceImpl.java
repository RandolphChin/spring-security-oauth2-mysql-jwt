package cn.randy.service.impl;

import cn.randy.entity.SysPermission;
import cn.randy.entity.SysRolePermission;
import cn.randy.entity.SysUserRole;
import cn.randy.repository.SysPermissionRepository;
import cn.randy.repository.SysRolePermissionRepository;
import cn.randy.repository.SysUserRoleRepository;
import cn.randy.service.MyPermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class MyPermissionServiceImpl implements MyPermissionService {
    @Autowired
    private SysUserRoleRepository sysUserRoleRepository;
    @Autowired
    private SysRolePermissionRepository sysRolePermissionRepository;
    @Autowired
    private SysPermissionRepository sysPermissionRepository;

    @Override
    public List<SysPermission> findByUserId(Integer userId) {
        List<SysUserRole> sysUserRoleList = sysUserRoleRepository.findByUserId(userId);
        if (CollectionUtils.isEmpty(sysUserRoleList)) {
            return null;
        }
        List<Integer> roleIdList = sysUserRoleList.stream().map(SysUserRole::getRoleId).collect(Collectors.toList());
        List<SysRolePermission> rolePermissionList = sysRolePermissionRepository.findByRoleIds(roleIdList);
        if (CollectionUtils.isEmpty(rolePermissionList)) {
            return null;
        }
        List<Integer> permissionIdList = rolePermissionList.stream().map(SysRolePermission::getPermissionId).distinct().collect(Collectors.toList());
        List<SysPermission> sysPermissionList = sysPermissionRepository.findByIds(permissionIdList);
        if (CollectionUtils.isEmpty(sysPermissionList)) {
            return null;
        }
        return sysPermissionList;
    }
}

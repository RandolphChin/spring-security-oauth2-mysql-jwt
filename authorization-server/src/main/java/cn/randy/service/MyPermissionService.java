package cn.randy.service;

import cn.randy.entity.SysPermission;

import java.util.List;


public interface MyPermissionService {
    List<SysPermission> findByUserId(Integer userId);
}

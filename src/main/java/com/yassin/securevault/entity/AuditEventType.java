package com.yassin.securevault.entity;

public enum AuditEventType {
    REGISTER_SUCCESS,
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    SECRET_CREATE,
    SECRET_READ,
    SECRET_UPDATE,
    SECRET_DELETE
}

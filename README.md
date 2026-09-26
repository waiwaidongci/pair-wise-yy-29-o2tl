# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/revocation-schedules`：预约撤销，登记原因与生效时刻；预约期间原证照常核验、同模板不再另发，相同幂等键重复提交沿用首次结果。
- `POST /api/revocation-schedules/{id}/cancel`：取消预约，记录取消人与取消时间；仅待生效的预约可取消。
- `GET /api/revocation-schedules`：按待生效、已生效、已取消分组列出预约记录（`GET /api/state` 的 `revocations` 字段相同）。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

预约撤销台分为三个业务文件：`revocation_desk.py`（预约受理）、`revocation_status.py`（状态判断）、`revocation_repository.py`（保存）。到点的预约在核验、取消或查询时即时应用，原证按撤销处理。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。

# pairwise-host-guard

反向代理接上多域名后，Host 头就成了可信输入：`Host: evil.example` 能进密码重置链接；后缀匹配把 `app.example.evil.com` 放过；端口和大小写没有归一，白名单判断失效；`user@host` 的 userinfo 被当成主机；IP 字面量绕过域名白名单；`X-Forwarded-Host` 整条链都信，攻击者能覆盖第一跳；缺 Host 时回落到默认域名；生产环境放行 localhost；尾部点号没处理；通配符写成 `*.example` 信任所有子域；IPv6 方括号解析错误；DNS 重绑定把解析结果换到内网地址。security/host_guard.py 是核心，tests/test_host_guard.py 15个红。要修的是：精确 host 匹配；后缀拒绝；端口归一；userinfo 拒绝；IP 字面量拒绝；转发链只信可信代理；缺 Host 拒绝；禁 localhost；尾部点归一；禁通配；IPv6 解析；重绑定校验。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。

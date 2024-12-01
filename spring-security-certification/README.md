# spring-security-certification
***
JWT（JSON Web Token）是一种无状态的认证方式，因为它不需要在服务器端维护会话或存储用户的登录状态。<br/>
JWT 将认证信息（例如用户身份、权限等）保存在客户端，并通过 HTTP 请求发送给服务器。服务器通过验证 JWT 是否有效来识别用户身份。<br/>
无状态（Stateless）：在 Spring Security 配置中，启用了 SessionCreationPolicy.STATELESS，这意味着服务器不会创建 HTTP 会话来保存用户的认证状态，而是每次请求都依赖于请求中携带的 JWT 信息

## JwtUtil

**功能：**
* 生成 JWT Token：使用用户信息生成一个 JSON Web Token。
* 验证 JWT Token：解析和验证传入的 JWT 是否有效，并提取用户信息。

**代码中的认证逻辑：** 
* 验证 JWT 时检查以下内容：
  *   是否签名正确。 
  *   是否过期。
* 认证的内容：
  *   从 JWT 中提取用户的 username

## SecurityConfig
**功能：**
* 配置 Spring Security 的核心安全规则。
* 定义哪些请求需要认证，哪些不需要认证。
* 配置自定义的 JWT 过滤器，实现无状态认证。
* 使用 JWTAuthenticationFilter 提取用户信息并验证身份

## AuthController

* 提供认证相关的接口，例如登录。
* 允许客户端调用 /api/auth/login 获取 JWT Token。

## AuthService

* 封装登录逻辑。
* 使用 AuthenticationManager 对用户进行认证。
* 在认证通过后，生成 JWT Token

## CustomerUserDetailsService

* 加载用户的详细信息（如用户名、密码、权限）供 Spring Security 使用。
* 模拟从数据库中加载用户。

## JWTAuthenticationFilter

* 拦截每个请求，检查是否携带 JWT Token。
* 验证 Token 的有效性，解析用户信息。
* 如果 Token 有效，将用户的认证信息存入 Spring Security 的上下文中。

***

**整体认证流程**
1. 用户登录：

   * 请求 /api/auth/login。
   * AuthController 调用 AuthService，由 AuthenticationManager 验证用户名和密码。
   * 验证成功后生成 JWT，返回给客户端。
2. 请求业务接口：

   * 客户端在 Authorization 请求头中携带 JWT。
   * JWTAuthenticationFilter 验证 Token 是否有效。
   * Token 有效则将用户信息存入 SecurityContextHolder。
   * Spring Security 验证是否有权限访问接口。
3. 保护业务接口：

   * 通过 SecurityConfig 配置：
   * 开放登录接口。
   * 其他接口需要用户认证，并根据用户权限访问。


***

**核心认证点的总结**
  * 用户凭据认证：AuthService 使用 AuthenticationManager 验证用户名和密码。
  * Token 验证：JWTAuthenticationFilter 验证请求中包含的 JWT 是否有效。
  * 权限校验：Spring Security 根据 SecurityContextHolder 中的认证信息决定是否允许访问接口。

  **这套代码通过 Spring Security 和 JWT，完整实现了 认证（Authentication） 和 授权（Authorization） 的流程**
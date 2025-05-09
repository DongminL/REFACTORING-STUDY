# **JwtUtil**

> **6.9 여러 함수를 클래스로 묶기**
> 

JwtUtil 클래스에 정의된 함수는 다음과 같습니다.

```java
public class JwtUtil{
  public String generateAccessToken(Authentication authentication);
  public String generateRefreshToken(Authentication authentication);	
  public Claims parseToken(String token);
  public Claims extractClaimsOrThrow(String type, String token);
  public String extractAccessToken(String bearerToken);
  public Authentication getAuthentication(String token);
  private CustomUserDetails authentication2User(Authentication authentiation);
  public void addBlackListExistingAccessToken(String accessToken, Date expirationDate);
  public boolean checkBlacklist(String accessToken);
  public void validateAccessTokenExpiration(Claims accessTokenClaims, String accessToken);
}
```

❓ **jwtUtil 클래스를 만들지 않았다면?**

만약 **`jwtUtil`**클래스를 만들지 않았다면, 토큰을 사용하는 서비스와 필터에서 메서드를 만들어야 할 것 입니다. 그렇게 되면 중복되는 코드가 발생하고, 책임이 분산되게 됩니다. 

✅ **jwtUtil 클래스를 작성하면서 얻은 효과**

jwt 토큰 관련 메서드를 **`jwtUtil`**에 모아서 중복을 방지했고, 토큰 관련 작업이라는 역할을 하는 클래스로 만들어서 응집도를 향상시킬 수 있었습니다.

<br><br><br><br>
> **8.1 함수 옮기기**
> 

JwtUtil 역할과 맞지 않는 메서드가 있다는 것을 발견했습니다.

```java
private CustomUserDetails authentication2User(Authentication authentiation);
```

이 메서드 **`Authentication`** 객체에서 **`CustomUserDetails`** 를 추출하는 기능으로, **JWT 처리와는 직접적인 관련이 없기 때문에 도메인 객체인 `CustomUserDetails` 에서 다루는 것이 더 자연스럽다**고 판단했습니다.
<br><br>
- 변경 전
    - JwtUtil
    
    ```java
    public String generateRefreshToken(Authentication authentication) {
    
            CustomUserDetails nowMember = authentication2User(authentication);
            Instant nowTime = Instant.now();
    ...
    }
    
    private CustomUserDetails authentication2User(Authentication authentication) {
           return (CustomUserDetails) authentication.getPrincipal();
    }
    ```
    
- 변경 후
    - CustomUserDetails
    
    ```java
    public static CustomUserDetails fromAuthentication (Authentication authentication) {
            return (CustomUserDetails) authentication.getPrincipal();
     }
    ```
    
    - jwtUtil
    
    ```java
    public String generateRefreshToken(Authentication authentication) {
    
            CustomUserDetails nowMember = CustomUserDetails.fromAuthentication(authentication);
            Instant nowTime = Instant.now();
    ...
    }
    ```
    

해당 기법을 적용하여 **`JwtUtil`**클래스는 **JWT관련 작업에 집중**하고, **`CustomUserDetails`**에서는 **자신과 관련된 책임**을 할 수 있도록 **응집도를 향상**시켰습니다.

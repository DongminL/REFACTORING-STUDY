# AuthService 코드악취 제거
# 기존코드

```java
@Slf4j
@RequiredArgsConstructor
@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final JwtService jwtService;
    private final MemberRepository memberRepository;
    private final FcmService fcmService;
    private final EmailService emailService;
    private final RedisTemplate<String, String> redisTemplate;
    static final String PREFIX = "auth:email:";

    public ReissueResponse reissue(String refreshToken, String accessToken) {
        NewTokenResponse newTokenResponse = jwtService.reissue(refreshToken, accessToken);
        HttpHeaders headers = new HttpHeaders();
        accessTokenSend2Client(headers, newTokenResponse.getAccessToken());
        refreshTokenSend2Client(headers, newTokenResponse.getRefreshToken(), 7);

        return new ReissueResponse(headers);
    }

    public LoginResponse login(
        String deviceTokenCookie,
        LoginRequest loginRequest
    ) {
        return commonLogin(deviceTokenCookie, loginRequest.getId(), loginRequest.getPassword());
    }

    public LoginResponse socialLogin(
        String deviceToken,
        SocialLoginRequest socialLoginRequest) {

        Member existMember = memberRepository.findByProviderAndSocialId(
                socialLoginRequest.getProvider(), socialLoginRequest.getSocialUserId())
            .orElse(null);

        if (existMember == null) {
            return LoginResponse.fail(MemberErrorCode.NOT_FOUND_MEMBER.getMessage());
        }

        return commonLogin(deviceToken, existMember.getEmail(), null);
    }

    private LoginResponse commonLogin(
        String deviceTokenCookie,
        String email, String password
    ) {

        Authentication authentication = null;
        try {
            authentication = createAuthentication(email, password);
        } catch (BusinessException e) {
            return LoginResponse.fail(e.getErrorCode().getMessage());
        }

        String accessToken = jwtUtil.generateAccessToken(authentication);
        String refreshToken = jwtUtil.generateRefreshToken(authentication);

        HttpHeaders headers = new HttpHeaders();
        accessTokenSend2Client(headers, accessToken);
        refreshTokenSend2Client(headers, refreshToken, 7);

        fcmService.loginToken(deviceTokenCookie);

        return LoginResponse.success(headers, createResponseBody(authentication));
    }

    public LogoutResponse logout(
        String deviceTokenCookie,
        String accessToken, String refreshToken
        ) {
        jwtService.logout(accessToken);
        fcmService.logoutToken(deviceTokenCookie);

        HttpHeaders headers = new HttpHeaders();
        refreshTokenSend2Client(headers, refreshToken, 0);

        return new LogoutResponse(headers);
    }

    public void emailVerification(EmailRequest emailRequest) {
        Member member = memberRepository.findByEmail(emailRequest.getEmail()).orElse(null);
        if (member == null || member.getMemberStatus() == MemberStatus.WITHDRAWAL) {
            throw new BusinessException(MemberErrorCode.NOT_FOUND_MEMBER);
        }
        emailService.sendEmail(emailRequest.getEmail());
    }

    public void verifyCode(VerifyCodeRequest verifyCodeRequest) {

        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        Purpose purpose = verifyCodeRequest.getPurpose();
        String email = verifyCodeRequest.getEmail();
        String code = verifyCodeRequest.getCode();

        String correctCode = valueOperations.get(PREFIX + email);

        if (correctCode == null) {
            throw new BusinessException(AuthErrorCode.INVALID_AUTH_CODE);
        } else if (!correctCode.equals(code)) {
            throw new BusinessException(AuthErrorCode.NOT_MATCH_AUTH_CODE);
        } else {
            redisTemplate.delete(PREFIX + email);

            // 인증된 사용자 저장
            String newPrefix = PREFIX + purpose.name().toLowerCase() + ":";
            valueOperations.set(newPrefix + email, "authenticated", 10,
                TimeUnit.MINUTES);
        }
    }

    private Authentication createAuthentication(String email, String password) {
        return authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(email, password));
    }

    private void accessTokenSend2Client(HttpHeaders headers, String accessToken) {
        headers.set("Authorization", "Bearer " + accessToken);
    }

    private void refreshTokenSend2Client(HttpHeaders headers, String refreshToken, long duration) {
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh-token", refreshToken)
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(Duration.ofDays(duration))
            .sameSite("None")
            .build();

        headers.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

    private MemberResponse createResponseBody(Authentication authentication) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Member loginMember = Member.builder()
            .memberId(userDetails.getMemberId())
            .email(userDetails.getEmail())
            .nickname(userDetails.getNickname())
            .profileImageUrl(userDetails.getProfileImageUrl())
            .role(userDetails.getRole())
            .memberStatus(userDetails.getStatus())
            .build();

        return MemberMapper.INSTANCE.toDto(loginMember);
    }
}
```

### 👃🏻 기존 코드의 문제점: 거대한 클래스

AuthService 클래스의 코드 악취는 **거대한 클래스**이다.

기존의 AuthService는 인증이라는 포괄적인 역할 안에서 **로그인, 로그아웃, 토큰 재발행, 이메일 인증**이라는 다양한 기능을 수행하고 있었다.  그러다보니 AuthService는 길어지고, **가독성이 떨어**졌다. 내가 아닌 다른 사람이 나의 코드를 보기에 복잡할 것 같다고 생각했다. 또한, 세부적으로는 다양한 역할을 수행하고 있어서 **결합도가 낮다**는 문제점도 존재했다.

<br><br>

# ✅리팩토링

### 1. 클래스 추출하기

> 👃🏻 하나의 클래스에 포괄적인 역할이 부여되어 **결합도가 낮다**.
> 

AuthService의 세부 기능을 기준으로 클래스를 분리했다.

- **`EmailVerificationService`**: 이메일 인증
    
    ```java
    public class EmailVerificationService {
        private final RedisTemplate<String, String> redisTemplate;
        static final String PREFIX = "auth:email:";
        
        public void verifyCode(VerifyCodeRequest verifyCodeRequest) {}
    }
    ```
    
- **`TokenService`** : 토큰 재발행하는 역할.
    
    ```java
    public class TokenService {
        private final JwtService jwtService;
      
        public ReissueResponse reissue(String refreshToken, String accessToken) {}
    }
    ```
    
- **`AuthService`** : 로그인, 로그아웃하는 역할.
    
    ```java
    public class AuthService {
        private final AuthenticationManager authenticationManager;
        private final JwtUtil jwtUtil;
        private final JwtService jwtService;
        private final MemberRepository memberRepository;
        private final FcmService fcmService;
    
        public LoginResponse login(String deviceTokenCookie, LoginRequest loginRequest) {}
        public LoginResponse socialLogin(String deviceToken, SocialLoginRequest socialLoginRequest) {}
        private LoginResponse commonLogin(String deviceTokenCookie,
            String email, String password) {}
        public LogoutResponse logout(String deviceTokenCookie,
            String accessToken, String refreshToken) {}
        private Authentication createAuthentication(String email, String password) {}
        private MemberResponse createResponseBody(Authentication authentication) {}
    }
    
    ```
    
- **`EmailSendService`**: 이메일 전송하는 역할.
    
    이메일 전송 시, 존재하는 이메일인지 검증하는 로직을 해당 클래스로 이동했다.
    
    ```java
    public class EmailSendService {
        private final RedisTemplate<String, String> redisTemplate;
        private final JavaMailSender javaMailSender;
        private final SpringTemplateEngine templateEngine;
        private final MemberRepository memberRepository;
        static final String PREFIX = "auth:email:";
        
        public void emailVerification(EmailRequest emailRequest) {}
        @Async
        public void sendEmail(String email) {}
        private String createCode() {}
        private String setContent(String code) {}
        private void codeSave(String email, String code) {}
    }
    ```
    

- **`TokenSettingUtil`** : 토큰의 변경사항을 헤더에 설정하는 역할

🚨 **문제점 발생**

AuthService와 TokenService로 나누면서 로그인, 로그아웃, 토큰 재발행에 사용되는 accessTokenSend2Client()와 refreshTokenSend2Client()에 대해  **코드 중복**이라는 악취가 발생하게 되었다.

👩🏻‍🔧 **해결 방법 1**

해당 로직을 정적 유틸 클래스인 TokenHeaderUtil로 분리했다. 해당 유틸 클래스는 jwtUtil 클래스와 다르게 다른 곳에서 값을 주입받을 필요가 없기 때문에 **정적 유틸 클래스**로 만들었다. 

```java
public class TokenSettingUtil {

    private TokenSettingUtil() {
        throw new UnsupportedOperationException("Utility class");
    }
    public static void accessTokenSend2Client(HttpHeaders headers, String accessToken) {
        headers.set("Authorization", "Bearer " + accessToken);
    }

    public static void refreshTokenSend2Client(HttpHeaders headers, String refreshToken,
        long duration) {
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh-token", refreshToken)
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(Duration.ofDays(duration))
            .sameSite("None")
            .build();

        headers.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }
}
```

🤔 **고민했던 부분**

정적 유틸 클래스의 문제점에 관한 글을 보았다.

> - 유틸클래스는 _결합도를 높일 수_ 있다.
> - 유틸클래스는 _객체 지향적이지 않다_.

내 생각엔 해당 유틸클래스가 HTTP 응답 헤더에 토큰 세팅이라는 단일 역할만 수행하고 있어 결합도가 높아진다는 문제점은 발생하지 않는다고 판단했다. 

그러나, 정적 메서드를 호출하여 **객체 지향적이지 못하다는 문제점이 존재했다.** 

<br>

👩🏻‍🔧 **해결 방법 2**

정적 메서드를 호출하는 방법 대신 메서드를 제공하는 객체를 생성하도록 변경했다.

```java
public class TokenSettingUtil {

    private final HttpHeaders headers;
    private final String accessToken;
    private final String refreshToken;
    private final Integer duration;

    public TokenSettingUtil(HttpHeaders headers, String accessToken, String refreshToken, Integer duration) {
        this.headers = headers;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.duration = duration;
    }

    public void accessTokenSend2Client() {
        this.headers.set("Authorization", "Bearer " + this.accessToken);
    }

    public void refreshTokenSend2Client() {
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh-token", refreshToken)
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(Duration.ofDays(this.duration))
            .sameSite("None")
            .build();

        this.headers.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }
}
```

위의 코드로 수정하여 AuthService, TokenService는 다음과 같이 Util 클래스를 사용할 수 있게 되었다.

```java
 TokenSettingUtil tokenSettingUtil = new TokenSettingUtil(headers, accessToken, refreshToken, 7);
 tokenSettingUtil.accessTokenSend2Client();
 tokenSettingUtil.refreshTokenSend2Client();
```

<br>

### 2. 이름 변경

> 👃🏻 **이름이 모호**한 코드 악취 존재
> 

기존 코드에서는 이메일을 사용하는 로그인을 기본 로그인으로 여겨 **`login` 이라는 메서드 명을 부여**하고 있었습니다. 그러나, 한 눈에 봤을 때 해당 메서드가 *공통된 로그인인지, 기본 로그인인지* 판단하기 어렵다는 생각을 했다.

따라서 login()을 **`emailLogin()` 으로 변경**했다.

```java
public LoginResponse emailLogin(
        String deviceTokenCookie,
        LoginRequest loginRequest
    ) {
        return commonLogin(deviceTokenCookie, loginRequest.getId(), loginRequest.getPassword());
    }
```
<br><br>

# 최종 코드

- AuthService
    
    ```java
    public class AuthService {
        private final AuthenticationManager authenticationManager;
        private final JwtUtil jwtUtil;
        private final JwtService jwtService;
        private final MemberRepository memberRepository;
        private final FcmService fcmService;
    
        public LoginResponse emailLogin(String deviceTokenCookie, LoginRequest loginRequest) {}
        public LoginResponse socialLogin(String deviceToken, SocialLoginRequest socialLoginRequest) {}
        private LoginResponse commonLogin(String deviceTokenCookie,
            String email, String password) {}
        public LogoutResponse logout(String deviceTokenCookie,
            String accessToken, String refreshToken) {}
        private Authentication createAuthentication(String email, String password) {}
        private MemberResponse createResponseBody(Authentication authentication) {}
    }
    ```
    

*다른 서비스 클래스 코드들이 이미 위에 존재하므로 다시 작성하지 않겠습니다.* 

해당 리팩토링을 통해 authService가 간결해졌다. 또한, 클래스 간 역할을 더 세부적으로 나누어 유지 보수하기 편해졌다.

기존 코드에서는 역할이 많아 AuthServiceTest에서도 굉장히 많은 역할이 있어 Nested를 통한 구조화가 이루어졌으나, 클래스를 분리함으로써 테스트 코드의 구조도 훨씬 간결해졌다.

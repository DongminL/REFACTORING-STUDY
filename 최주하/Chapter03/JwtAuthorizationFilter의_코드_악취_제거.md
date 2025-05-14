### 기존 코드

```java
public class JwtAuthorizationFilter extends OncePerRequestFilter{
...
@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        if (isExcludedPath(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = null;

        try {
            log.info("Access token: {}", request.getHeader("Authorization"));
            accessToken = jwtUtil.extractAccessToken(request.getHeader("Authorization"));
            jwtUtil.parseToken(accessToken);
        } catch (BusinessException e) {
            if (e.getErrorCode() == TokenErrorCode.ACCESS_TOKEN_NOT_EXIST) {
                if (antPathMatcher.match("/ws/**", request.getRequestURI())) {
                    filterChain.doFilter(request, response);
                    return;
                }
                request.setAttribute(EXCEPTION_ATTRIBUTE, "ACCESS_TOKEN_NOT_EXIST");
                throw new BusinessException(TokenErrorCode.ACCESS_TOKEN_NOT_EXIST);
            }
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            log.info(e.getMessage());
            request.setAttribute(EXCEPTION_ATTRIBUTE, "INVALID_TOKEN");
            throw new BusinessException(TokenErrorCode.INVALID_TOKEN);
        } catch (ExpiredJwtException e) {
            log.info(e.getMessage());
            request.setAttribute(EXCEPTION_ATTRIBUTE, "EXPIRED_ACCESS_TOKEN");
            throw new BusinessException(TokenErrorCode.EXPIRED_ACCESS_TOKEN);
        }

        if (jwtUtil.checkBlacklist(accessToken)) {

            request.setAttribute(EXCEPTION_ATTRIBUTE, "INVALID_TOKEN");
            throw new BusinessException(TokenErrorCode.INVALID_TOKEN);
        }

        Authentication authentication = jwtUtil.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }

    private boolean isExcludedPath(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();

        boolean isExcludedOnlyGetMethod = excludeGetPaths.stream()
            .anyMatch(pattern -> antPathMatcher.match(pattern, path) && method.equals("GET"));
        boolean isExcluded = excludeAllPaths.stream()
            .anyMatch(pattern -> antPathMatcher.match(pattern, path));

        return (isExcluded || isExcludedOnlyGetMethod);
    }
}
```
<br>

## ✅ 리팩토링

### 1. 필드명과 메서드명 바꾸기

> 👃🏻 ***이름이 명확한 의도를 표현하지 않는다*는 코드 악취 존재**
> 

**`JwtAuthorizationFilter`** 에서 가장 먼저 리팩토링한 것은 바로 필드명과 메서드명이다.

- **isExcludedPath(HttpServletRequest request) → isPathWithoutFilter(HttpServletRequest request)**

isExcludedPath 메서드는 필터를 거치는 경로인지에 대해 판단한다. 그러나, 메서드 명만으로는 메서드의 목적이 잘 드러나지 않는 것 같다고 생각하여 **`isPathWithoutFilter`** 라는 이름으로 변경했다.

<br>

### 2. 함수 추출하기

> 👃🏻 ***doInternalFilter()의 길이가 너무 길다*는 코드 악취 존재**
> 

doFilterInternal()이 길이가 길기 때문에 이를 **`함수 추출하기`** 를 사용하여 길이를 줄이고 가독성을 향상 시킬 수 있도록 했다.

- **validateNotBlacklistedToken()**

```java
private void validateNotBlacklistedToken(String accessToken, HttpServletRequest request) {
    if (jwtUtil.checkBlacklist(accessToken)) {
        request.setAttribute(EXCEPTION_ATTRIBUTE, "INVALID_TOKEN");
        throw new BusinessException(TokenErrorCode.INVALID_TOKEN);
    }
}
```

코드 자체가 단순해서 읽기 쉽다. 메서드로 분리하면, 흐름을 단계적으로 읽기 쉬워져서 가독성이 향상될 것이라고 생각했다. 또한, 토큰이 블랙리스트에 등록되었는지 확인하고 예외를 던지는 역할만 수행하므로, *블랙리스트 검증*이라는  단일 책임만 가진다고 생각해서 메서드로 분리하기 적합하다고 생각했다.

- **setAuthentication()**

```java
private void setAuthentication(String accessToken){
    Authentication authentication = jwtUtil.getAuthentication(accessToken);
		SecurityContextHolder.getContext().setAuthentication(authentication);
}
```

마찬가지로 setAuthenitcation()이라는 메서드명만으로도 filter 흐름을 이해하기 쉽도록 메서드로 추출해주었다. 

메서드 내부에서 인증 객체를 만들고, SecurityContextHolder에 넣는 두 가지 동작을 하지만, 두 가지 동작이 **인증 상태를 설정**한다는 하나의 역할이라고 생각해서 추출을 진행했다.

<br>

> **그 외) 가독성 향상을 위한 리팩토링**
> 
- **checkPathWithGetMethod() , checkOnlyPath()**

기존에는 isPathWithoutFilter 메서드의 코드가 다음과 같았다.

```java
 private boolean isPathWithoutFilter(HttpServletRequest request){
		 String path = request.getRequestURI();
     String method = request.getMethod();

     boolean isExcludedOnlyGetMethod = excludeGetPaths.stream()
            .anyMatch(pattern -> antPathMatcher.match(pattern, path) && method.equals("GET"));
     boolean isExcludedAllMethod = excludeAllPaths.stream()
            .anyMatch(pattern -> antPathMatcher.match(pattern, path));

     return (isExcludedAllMethod || isExcludedOnlyGetMethod);
}
```
<br>
isExcludedOnlyGetMethod와 isExcludedAllMethod 변수를 작성한 목적은 return문에서 가독성을 높이기 위함이었다. 그러나, 함수로 추출하면, 굳이 변수를 만들지 않고도 가독성을 유지할 수 있다고 생각했다. 

```java
private boolean isPathWithoutFilter(HttpServletRequest request) {
    return (checkPathWithGetMethod(request) || checkOnlyPath(request));
}

private boolean checkPathWithGetMethod(HttpServletRequest request) {
   return excludeGetPaths.stream()
        .anyMatch(pattern -> antPathMatcher.match(pattern, request.getRequestURI()) && request.getMethod().equals("GET"));
}

private boolean checkOnlyPath(HttpServletRequest request) {
   return excludeAllPaths.stream()
        .anyMatch(pattern -> antPathMatcher.match(pattern, request.getRequestURI()));
}
```

<br>

## 💡 최종 코드

```java
@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        if (isPathWithoutFilter(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = null;

        try {
            log.info("Access token: {}", request.getHeader("Authorization"));
            accessToken = jwtUtil.extractAccessToken(request.getHeader("Authorization"));
            jwtUtil.parseToken(accessToken);
        } catch (BusinessException e) {
            if (e.getErrorCode() == TokenErrorCode.ACCESS_TOKEN_NOT_EXIST) {
                if (antPathMatcher.match("/ws/**", request.getRequestURI())) {
                    filterChain.doFilter(request, response);
                    return;
                }
                request.setAttribute(EXCEPTION_ATTRIBUTE, "ACCESS_TOKEN_NOT_EXIST");
                throw new BusinessException(TokenErrorCode.ACCESS_TOKEN_NOT_EXIST);
            }
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            log.info(e.getMessage());
            request.setAttribute(EXCEPTION_ATTRIBUTE, "INVALID_TOKEN");
            throw new BusinessException(TokenErrorCode.INVALID_TOKEN);
        } catch (ExpiredJwtException e) {
            log.info(e.getMessage());
            request.setAttribute(EXCEPTION_ATTRIBUTE, "EXPIRED_ACCESS_TOKEN");
            throw new BusinessException(TokenErrorCode.EXPIRED_ACCESS_TOKEN);
        }

        validateNotBlacklistedToken(accessToken, request);
        setAuthentication(accessToken);

        filterChain.doFilter(request, response);
    }
```

리팩토링을 하고나서 doInternalFilter의 흐름을 읽기가 더 수월해졌다.

<br>

## 🤔 고민했으나 적용하지 않은 것

- 경로 확인 로직을 메서드로 추출하기

```java
 private void checkPath(FilterChain filterChain, HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
		    if (isPathWithoutFilter(request)) {
            filterChain.doFilter(request, response);
            return;
        }
    }
```

원래는 경로 확인 로직을 위와 같이 checkPath 메서드로 추출하려고 했다. 그러나, 메서드로 추출하게 되면, 다음 필터를 실행하고 돌아와 JwtAuthorizationFilter를 거치게 되어 인증에 문제가 생긴다. 따라서 해당 로직을 추출하지 않았다.

<br>

- try-catch문을 메서드로 추출하기

try-catch문을 통해 jwtUtil에서 accessToken을 추출하고, 유효한 지 검증하는 로직이 있다. 이 로직의 길이가 길고, catch로 예외를 잡는 부분이 반복되어 가독성을 해친다고 생각했다.  그러나 다음과 같은 이유로 분리하지 않았다.

1. doFilterInternal로 들어오는 매개변수를 모두 넘겨주어야 한다. 이는 저 부분이 필터의 핵심 로직이라는 것을 의미한다고 생각한다. 따라서, 핵심 로직을 분리하기보다는 그냥 기존 코드 처럼 두는 것이 좋다고 생각했다.
2. 경로 확인 로직을 분리했을 때와 같은 문제점이 발생한다. catch문 내에서 웹소켓 경로로 접근하는 경우에는 액세스 코드가 없어도 예외를 던지지 않고, 다음 필터로 넘어가야 하는데 메서드로 분리할 경우, 인증 필터를 거치게 되어 문제가 발생한다.

<br>

- catch의 중복 코드를 없애기

catch에서 로그를 출력하고, request에 exception_attribute를 설정하고, 예외를 던지는 패턴이 중복되어 이를 해결하고자 했다. 그러나, Attribute를 초기화 하는 문구와 예외가 각기 다르고, 코드의 복잡도가 높지 않다고 생각해 기존 코드를 유지했다.

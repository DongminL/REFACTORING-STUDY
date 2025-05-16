# 놓친 버그를 잡을 때, 유용한 TDD

## 버그 재현 테스트 코드 작성

``` java
@DisplayName("동시에 많은 좋아요 추가 요청이 발생할 때, 좋아요 개수의 정합성 확인")
@Test
void IsNotEqualLikeCount() throws InterruptedException {
    // given
    int threadCount = 1000; // 스레드 개수
    ExecutorService executorService = Executors.newFixedThreadPool(threadCount); // 스레드 풀 생성
    CountDownLatch latch = new CountDownLatch(threadCount); // 스레드 대기 관리

    String subject = "test subject";
    String content = "test content";
    FeedbackWriteRequest request = new FeedbackWriteRequest(subject, content);
    Feedback savedFeedback = feedbackRepository.saveAndFlush(Feedback.create(request, member));

    // when
    for (int i = 0; i < threadCount; i++) {
        executorService.submit(() -> {
            try {
                CustomUser2Member user = new CustomUser2Member(
                    new CustomUserDetails(member.getMemberId(), "", "",
                        "", "", MemberRole.USER, MemberStatus.ACTIVITY));
                likeService.addLike(savedFeedback.getFeedbackId(), user);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                latch.countDown();
            }
        });
    }

    // 스레드가 다 끝날 때까지 기다리기
    latch.await();
    executorService.shutdown();

    // then
    Feedback updatedFeedback = feedbackRepository.findById(savedFeedback.getFeedbackId()).get();
    assertThat(updatedFeedback.getLikeCount()).isEqualTo(threadCount);
}
```

해당 테스트 코드는 데이터의 정합성이 잘 지켜지는지 확인하는 테스트다.

### 커밋 남기기
---

![](https://velog.velcdn.com/images/milkskfk5677/post/2122dbcf-ab7c-4736-ae6b-2682d9325dc3/image.png)

커밋을 남긴 뒤 push 하여 CI가 실패했음을 기록으로 남겼다.

![](https://velog.velcdn.com/images/milkskfk5677/post/6f1cb560-9725-4e2f-86d2-11289062bbc4/image.png)

해당 커밋을 확인해보면 어떤 테스트가 어떻게 실패했음을 알 수 있어 버그 리포트로도 활용될 수 있다.

<br>

## 버그 해결 후 테스트 

해당 버그 내용은 [이전 글](https://velog.io/@milkskfk5677/Spring-Batch-Redis%EB%A5%BC-%EC%82%AC%EC%9A%A9%ED%95%98%EC%97%AC-%EB%8D%B0%EC%9D%B4%ED%84%B0%EC%9D%98-%EC%A0%95%ED%95%A9%EC%84%B1-%EC%9C%A0%EC%A7%80%ED%95%98%EA%B8%B0)에서 다뤘기 때문에, 여기서는 넘어가려고 한다. 

![](https://velog.velcdn.com/images/milkskfk5677/post/1b8909d4-41b0-42e4-bdc5-ffcf55793461/image.png)

버그 해결 이후 위의 테스트를 성공했고, 수정한 사항을 서버에 반영까지 했다.

이걸 통해 느낀 TDD의 장점은 아래와 같다.

### TDD의 장점
---

- 테스트의 실패를 확인하고 기록했으니, 이 테스트가 성공하도록 기존 코드를 어떻게 변경해야 할지 고민하게 된다. 

- 테스트 이후 제품 코드의 목적이 명확해진다.

- 수정할 때마다 테스트해 볼 수 있어 진행 과정이 안정적이게 된 것 같다.

<br>

## TDD에 관한 개인적인 의견

물론 마틴 파울러는 TDD를 추천하지만, 모든 코드를 작성할 때 TDD 방식을 따르기에는 비효율적이라는 생각이 든다. 예를 들어, 간단한 코드나 충분히 검증된 라이브러리리 또는 API를 사용하는 경우처럼 모든 코드를 테스트하기는 굳이(?) 싶다. 비슷하게 책에서도 "테스트에도 수확 체감 법칙이 적용된다."라는 내용이 있어, 위험한 부분에 집중하여 테스트 코드를 작성하는 것이 좋을 것 같다. 그래서 나는 새로운 버그를 수정할 때와 정리도 힘들 정도로 복잡한 로직을 구현할 때만 TDD 방식을 따르려고 한다.

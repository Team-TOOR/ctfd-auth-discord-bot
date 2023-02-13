## 봇 세팅
1. 필요한 패키지 설치
```
pip install -r requirements.txt
```

2. 봇 권한 설정 및 서버에 추가<br>
*권한*<br>
oauth -> URL generator -> Scopes에 `bot`, `applications.commands` 활성화 -> Bot Permissions에 `Administrator` 활성화

3. 인증 채널 생성

4. 인증 로그 채널 생성 후 권한 설정<br>인증 로그 채널은 반드시 비공개 채널이어야 합니다.

5. 인증 대기 역할 생성

6. 인증 봇 권한 설정<br>서버 설정 -> 역할 -> 인증봇을 최상단으로 끌어오기
<img width="709" alt="스크린샷 2023-02-13 오후 7 08 46" src="https://user-images.githubusercontent.com/83567597/218429558-b02a82c1-464a-49a8-8396-0990323b116f.png">

7. .env 파일 생성 후 작성<br>오른쪽 클릭을 통해 서버, 역할의 ID를 복사할 수 있습니다.

8. 봇 실행
```
python app.py
```

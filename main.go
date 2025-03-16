package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/natefinch/lumberjack"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	ginlimiter "github.com/ulule/limiter/v3/drivers/middleware/gin"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"
	"golang.org/x/crypto/bcrypt"

	"auth-svr-jagal/loader"
	"auth-svr-jagal/models"
	"auth-svr-jagal/utils"
	"auth-svr-jagal/viewm"
)

// This Gin server will be deployed on AWS in the future.
// The server will use EC2 for hosting the application
// and RDS (PostgreSQL) for database management.
// 이 Gin 서버는 추후 AWS에 배포될 예정입니다.
// 애플리케이션은 EC2를 사용하여 호스팅되며,
// 데이터베이스 관리는 RDS(PostgreSQL)를 사용할 계획입니다.

// curl을 이용한 RESTful 요청 테스트
// curl -X POST -H "Content-Type: application/json" -d '{"userId": "jagalmon", "userPass": "pass123", "twoFaToken":"", "captchaToken":"", "deviceCd":"", "platformCd":"", "browserCd":"", "rememberMe":"N"}' http://localhost:8080/login
// 추후 프론트엔드 서버(react + nextjs) 들어올때 까지는 curl로 테스트

type appContext struct {
	sk []byte // signKey
	rc *redis.Client
	db *sqlx.DB
	pl *loader.PluginLoader
}

var (
	ctx *appContext

	// 로그인 요청 수 메트릭
	loginRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_requests_total",
			Help: "Total number of login requests",
		},
		[]string{"status"}, // 성공("success") 또는 실패("failure")
	)

	// 로그인 요청 처리 시간 메트릭
	loginDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "login_request_duration_seconds",
			Help:    "Histogram of login request durations in seconds",
			Buckets: prometheus.DefBuckets, // 기본 버킷 사용
		},
		[]string{"endpoint"},
	)

	// server.log 파일과 queries.log 파일을 분리
	qryLog = log.New(&lumberjack.Logger{
		Filename:   "./logs/queries.log",
		MaxSize:    10,    // 새로운 파일로 롤오버 되는 기준(단위는 MB)
		MaxBackups: 1,     // 롤오버된 파일의 보관 개수
		MaxAge:     30,    // 백업 로그 보관 일시
		Compress:   false, // 백업 로그 gzip 압축 여부
	}, "", log.LstdFlags)
)

func init() {
	if err := godotenv.Load("config.env"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	prometheus.MustRegister(loginRequests)
	prometheus.MustRegister(loginDuration)
}

func main() {
	gin.DefaultWriter = os.Stdout
	gin.DefaultErrorWriter = os.Stderr

	// 추후 분산 로깅 서버(Datadog) 들어오면 로그 수집 도구 패키지 설치해서 추가 예정
	// 그 전까지는 lumberjack 패키지를 이용해 파일로 log 관리
	log.SetOutput(&lumberjack.Logger{
		Filename:   "./logs/server.log",
		MaxSize:    10,    // 새로운 파일로 롤오버 되는 기준(단위는 MB)
		MaxBackups: 1,     // 롤오버된 파일의 보관 개수
		MaxAge:     30,    // 백업 로그 보관 일시
		Compress:   false, // 백업 로그 gzip 압축 여부
	})

	ctx = &appContext{
		sk: []byte(os.Getenv("JWT_SIGN_KEY")), // 🔑 JWT 서명 키(추후 클라우드 기반 Key Management Service로 서명 키 관리 예정)
		pl: loader.NewPluginLoader(),          // 🔌 플러그인 로더(.so(Shared Object) 사용)
	}

	plugins := map[string]string{
		"log_utils":    "./mylib/log_utils.so",
		"crypto_utils": "./mylib/crypto_utils.so",
	}

	for name, path := range plugins {
		if err := ctx.pl.LoadPlugin(name, path); err != nil {
			log.Fatalf("Failed to load plugin '%s': %v", name, err)
		}
	}

	result, err := ctx.pl.ExecutePlugin("log_utils", "./logs/server.log", "./logs/queries.log")
	if err != nil {
		log.Fatalf("Failed to execute plugin: %v", err)
	}

	if rotated, ok := result["rotated"]; ok {
		log.Println("Rotated Files: ", rotated)
	}

	ctx.rc = initRedis() // 🗄️ Redis 연결
	ctx.db = initDB()    // 💾 DB 연결

	defer func() { // 개별 리소스 defer를 사용하지 않고 익명 함수 defer를 사용
		if err := recover(); err != nil { // recover가 없으면 패닉 발생 시 서버 종료되나 recover가 있으면 패닉 복구 가능
			log.Printf("Panic occurred: %v", err)
		}

		if err := ctx.db.Close(); err != nil {
			log.Printf("Failed to close Database: %v", err)
		} else {
			log.Println("Database connection closed successfully.")
		}

		if err := ctx.rc.Close(); err != nil {
			log.Printf("Failed to close Redis: %v", err)
		} else {
			log.Println("Redis connection closed successfully.")
		}
	}()

	/*
		// 트래픽 제한(ulule 유룰)
	*/
	middleware := createRateLimiter(ctx.rc)

	/*
		// Golang Gin Server
	*/
	r := setupRouter(middleware) // 진 라우터 초기화

	// ECC SSL 인증서 적용
	cert, err := tls.LoadX509KeyPair("certs/ssl-cert.crt", "certs/ssl-cert.key")
	if err != nil {
		panic(err)
	}

	//r.Run(":" + os.Getenv("SVR_PORT"))
	svr := &http.Server{ // 추후 app 서버와 연동하기 위해 mTLS 설정 추가 예정
		Addr:    ":" + os.Getenv("SVR_PORT"),
		Handler: r,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	go func() { // nextjs의 hot reload를 사용하기 위해 aws 올라가기 전까지는 https 사용하지 않기
		//if err := svr.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v\n", err)
		}
	}()

	log.Println("========== SERVER START ==========")
	log.Println("🚀 Server is running")
	log.Println("==================================")

	gracefulShutdown(svr)
}

/*
// ===========================================
// Database
// ===========================================
*/

func initRedis() *redis.Client {
	redisAddr := os.Getenv("REDIS_URL") + ":6379"
	// 추후 aws 올라갈때 multi node redis 방식으로 전환 예정
	// 추후 multi region redis 방식으로 전환 예정

	client := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	return client
}

/*
func flushAllRedis() error {
	log.Println("Flushing all Redis data...")
	result, err := redisClient.FlushAll(context.Background()).Result()
	if err != nil {
		return err
	}
	log.Printf("Redis flush result: %s", result)
	return nil
}
*/

func deleteKeysRedis(prefixes ...string) error {
	for _, prefix := range prefixes {
		var cursor uint64
		for {
			keys, nextCursor, err := ctx.rc.Scan(context.Background(), cursor, prefix+"*", 100).Result()
			if err != nil {
				return fmt.Errorf("failed to scan keys with prefix %s: %v", prefix, err)
			}
			cursor = nextCursor

			if len(keys) > 0 {
				if _, err := ctx.rc.Del(context.Background(), keys...).Result(); err != nil { // 키 삭제
					return fmt.Errorf("failed to delete keys with prefix %s: %v", prefix, err)
				}
			}

			if cursor == 0 {
				break // 스캔 완료
			}
		}
	}
	return nil
}

func initDB() *sqlx.DB {
	// 암복호화는 AES-256-GCM 알고리즘 사용
	// 추후 대칭키 방식이 아닌 비대칭 알고리즘으로 대체 예정
	result, err := ctx.pl.ExecutePlugin("crypto_utils", "decrypt", os.Getenv("DB_PASS"))
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	decDbPass, ok := result["result"].(string)
	if !ok {
		log.Fatalf("Failed to convert result to string")
	}

	dsn := "user=" + os.Getenv("DB_USER") +
		" password=" + decDbPass +
		" dbname=" + os.Getenv("DB_NAME") +
		" sslmode=disable"
	// 추후 database sharding 으로 분산 처리 예정(data center 단위 처리)
	// 더 추후 multi region clustering을 이용한 분산 데이터베이스로 변경 예정(region 단위 처리)

	db, err := sqlx.Open(os.Getenv("DB_DRIVER"), dsn) // sqlx는 Open() 내부에서 커넥션 풀 자동으로 생성
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// 커넥션 풀 설정
	db.SetMaxOpenConns(utils.ParseEnvInt(os.Getenv("CONN_MAX_OPEN"), 0))
	db.SetMaxIdleConns(utils.ParseEnvInt(os.Getenv("CONN_MAX_IDLE"), 0))
	db.SetConnMaxLifetime(time.Duration(utils.ParseEnvInt(os.Getenv("CONN_MAX_LIFETIME"), 0)) * time.Minute)

	return db
}

func loadQueries(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	queries := make(map[string]string)
	var currentName string
	var currentQuery strings.Builder
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "-- name:") { // 쿼리 이름 시작
			if currentName != "" && currentQuery.Len() > 0 { // 이전 쿼리 저장
				queries[currentName] = currentQuery.String()
				currentQuery.Reset()
			}
			currentName = strings.TrimSpace(strings.TrimPrefix(line, "-- name:"))
		} else if line == ";" { // 쿼리 끝
			if currentName != "" && currentQuery.Len() > 0 {
				queries[currentName] = currentQuery.String()
				currentQuery.Reset()
			}
			currentName = "" // 현재 쿼리 완료 후 초기화
		} else if currentName != "" { // 현재 쿼리 내용 추가
			currentQuery.WriteString(line + "\n")
		}
	}

	// 파일 끝에 도달한 마지막 쿼리 저장
	if currentName != "" && currentQuery.Len() > 0 {
		queries[currentName] = currentQuery.String()
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return queries, nil
}

func printQueryWithParams(query string, params map[string]interface{}) string {
	for key, value := range params {
		placeholder := fmt.Sprintf(":%s", key)
		query = strings.ReplaceAll(query, placeholder, fmt.Sprintf("'%v'", value))
	}

	qryLog.Printf("Whole Query: [%s]\n", query)

	return query
}

/*
// ===========================================
// Router/Handler
// ===========================================
*/

func setupRouter(middleware gin.HandlerFunc) *gin.Engine {
	r := gin.Default()

	webSvrOrigins := "http://" + os.Getenv("FE_URL") + ":" + os.Getenv("FE_PORT")

	// CORS 설정
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{webSvrOrigins}, // react 웹서버의 주소
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
	}))

	r.Use(middleware) // 트래픽 제한 미들웨어

	queries, err := loadQueries("queries/login.sql")
	if err != nil {
		log.Fatalf("Failed to load queries: %v", err)
		return r
	}

	// 로그인 엔드포인트
	r.POST("/login", func(c *gin.Context) {
		loginHandler(c, queries)
	})

	// 회원가입 엔드포인트
	r.POST("/signup", func(c *gin.Context) {
		signupHandler(c, queries)
	})

	// protected 엔드포인트 그룹
	protected := r.Group("/protected")
	protected.Use(authMiddleware())          // access token 검증 미들웨어(추후 추가 검증 예정, 2FA, CAPTCHA)
	protected.Use(activityTimeoutMiddleware) // 타임아웃 판단 미들웨어
	protected.GET("/", protectedHandler)

	// auth 서버 자체 서비스 엔드포인트(이 핸들러들부터 다른 경로/파일로 분리)
	//protected.GET("/users", getUsers)
	//protected.POST("/createUser", setCreateUser)
	//protected.POST("/modifyUser", setModityUser)
	//protected.GET("/manage", getManageInfo)
	//protected.POST("/modifyManage", setModityManageInfo)

	// 이하 app 서버의 엔드포인트
	//protected.GET("/authInfo", getAuthInfo)

	// 로그아웃 엔드포인트
	protected.POST("/logout", func(c *gin.Context) {
		logoutHandler(c)
	})

	// 헬스 체크 엔드포인트(for 로드 밸런서)
	// curl -X GET http://localhost:8080/healthz
	r.GET("/healthz", healthCheckHandler)

	// Prometheus 엔드포인트(for 프로메테우스/그라파나/APM도구)
	// curl -X GET http://localhost:8080/metrics
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return r
}

func signupHandler(c *gin.Context, queries map[string]string) {
	//startTime := time.Now()
	signupData := viewm.SignupRequestDto{}

	if c.ContentType() != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "Content-Type must be application/json"})
		return
	}

	if err := c.ShouldBindJSON(&signupData); err != nil {
		log.Println("Bind Error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input data", "details": err.Error()})
		return
	}

	// user_id 중복 체크
	checkUserQuery := queries["check_user_id"]
	params := map[string]interface{}{
		"user_id": signupData.UserId,
	}

	rows, err := ctx.db.NamedQuery(checkUserQuery, params)
	if err != nil {
		log.Printf("Database error during user ID check: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	if rows.Next() {
		response := viewm.LoginResponsetDto{
			Header: viewm.Header{
				Code:    "ERR",
				Message: "User ID already exists.",
			},
		}
		c.JSON(http.StatusConflict, response)
		return
	}

	// 비밀번호 bcrypt 해싱
	// signup은 빈도가 낮아 당장 goroutine 없어도 됨
	// 추후 goroutine 처리 예정
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(signupData.UserPass), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Password hashing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password hashing failed"})
		return
	}

	// 회원가입 쿼리 실행
	insertUserQuery := queries["set_user_info"]
	params = map[string]interface{}{
		"user_id":        signupData.UserId,
		"user_pass":      string(hashedPass),
		"user_name":      signupData.UserName,
		"user_nickname":  signupData.UserNickname,
		"user_email":     signupData.UserEmail,
		"user_phone":     signupData.UserPhone,
		"user_image_url": nil,
		"user_addr":      nil,
		"team_cd":        nil,
		"role_cd":        nil,
	}

	_, err = ctx.db.NamedExec(insertUserQuery, params)
	if err != nil {
		log.Printf("Failed to insert user info: %v", err)
		response := viewm.LoginResponsetDto{
			Header: viewm.Header{
				Code:    "ERR",
				Message: "Failed to sign up. Please try again.",
			},
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}

	// 회원가입 성공 응답
	response := viewm.LoginResponsetDto{
		Header: viewm.Header{
			Code:    "OK",
			Message: "Signup successful. Please log in.",
		},
	}
	c.JSON(http.StatusOK, response)

	// 처리 시간 기록
	//duration := time.Since(startTime).Seconds()
	//signupDuration.WithLabelValues("/signup").Observe(duration)
}

func loginHandler(c *gin.Context, queries map[string]string) {
	startTime := time.Now()
	loginData := viewm.LoginRequestDto{}

	if c.ContentType() != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "Content-Type must be application/json"})
		return
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		log.Println("Bind Error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input data", "details": err.Error()})
		return
	}

	if loginData.UserId == "" || loginData.UserPass == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing user_id or password"})
		return
	}

	validId := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !validId.MatchString(loginData.UserId) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID format"})
		return
	}

	sessionKey := fmt.Sprintf("session:%s", loginData.UserId)
	exists, err := ctx.rc.Exists(context.Background(), sessionKey).Result() // 중복 로그인 체크
	if err != nil {
		log.Fatalf("Failed to check key existence: %v", err)
	}

	if exists > 0 { // 중복 로그인 여부
		log.Printf("Duplicate login attempt detected for user_id: %s", loginData.UserId)
		/*
			c.JSON(http.StatusConflict, gin.H{
				"error":   "Duplicate login detected",
				"message": "You are already logged in from another device. Please log out first.",
			}) // 추후 기존 로그인 유저에게 알림 주기 위한 websocket 송수신 추가 예정
			//return // 현재로서는 일단 중복 로그인 허용
		*/
	}

	getUserPassQuery := queries["get_user_pass"]

	var resultLogin models.ResultLoginDto
	params := map[string]interface{}{
		"user_id": loginData.UserId,
	}
	printQueryWithParams(getUserPassQuery, params)

	rows, err := ctx.db.NamedQuery(getUserPassQuery, params)
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()

	if !rows.Next() {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database no rows"})
		return
	}

	for {
		//if err := rows.Scan(&resultPass); err != nil { // 단일 컬럼 조회시
		if err := rows.StructScan(&resultLogin); err != nil { // 여러 컬럼 조회시
			log.Printf("Error scanning row: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error scanning row"})
			//break
			return
		}

		if !rows.Next() {
			break
		}
	}

	var inputPass string
	if len(resultLogin.ResultPass) == 60 &&
		(resultLogin.ResultPass[:4] == "$2a$" || resultLogin.ResultPass[:4] == "$2b$") { // 디비 패스워드가 해싱
		log.Println("The database password has been hashed.")

		resultCh := make(chan []byte)
		errorCh := make(chan error)

		hashPasswordAsync(loginData.UserPass, resultCh, errorCh) // 비크립트 해싱 알고리즘으로 해싱

		select {
		case hashedVl := <-resultCh:
			//c.JSON(http.StatusCreated, gin.H{"Hashed password": string(hashed)})
			inputPass = string(hashedVl) // 인풋 패스워드를 해싱
		case err := <-errorCh:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Error hashing password", "details": err.Error()})
		}

	} else { // 디비 패스워드가 노해싱
		log.Println("The database password has not been hashed.")
		inputPass = loginData.UserPass // 인풋 패스워드를 노해싱
	}

	success := true
	if resultLogin.ResultPass == inputPass { // 패스워드 일치
		log.Println("Password matches.")

		accessToken, err := generateToken(loginData.UserId) // access token 생성
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token", "defails": err.Error()})
			//return
		}
		// 추후 oauth 2.0 방식 적용 예정.

		log.Println("access token: ", accessToken)
		c.Header("Authorization", "Bearer "+accessToken)

		response := viewm.LoginResponsetDto{
			Header: viewm.Header{
				Code:    "OK",
				Message: "Login Successful",
			},
			AccessToken:  accessToken, // 불필요하나 일단 냅둠
			UserName:     resultLogin.UserName,
			UserNickname: resultLogin.UserNickname.String,
			UserEmail:    resultLogin.UserEmail.String,
			UserPhone:    resultLogin.UserPhone.String,
			UserImageUrl: resultLogin.UserImageUrl.String,
			RoleCd:       resultLogin.RoleCd.String,
			TeamCd:       resultLogin.TeamCd.String,
		}
		c.JSON(http.StatusOK, response) // access token 리턴

		ctx.rc.Set(context.Background(), sessionKey, accessToken, 0) // access token 저장
		// 추후 refresh token 방식 적용 예정. refresh token 방식 적용시 access token의 TTL을 time.Hour*24 으로 설정

		activityKey := fmt.Sprintf("last_activity:%s", loginData.UserId)
		ctx.rc.Set(context.Background(), activityKey, time.Now().Unix(), 0) // 마지막 활동 시간 저장

		setLastLoginQuery := queries["set_last_login"]
		params := map[string]interface{}{
			"user_id":       loginData.UserId,
			"last_login_ip": c.ClientIP(),
		}
		printQueryWithParams(setLastLoginQuery, params)

		result, err := ctx.db.NamedExec(setLastLoginQuery, params)
		if err != nil {
			log.Printf("Failed to execute setLastLoginQuery: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update last login"})
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			log.Printf("No rows updated for user_id: %s", loginData.UserId)
		} else {
			log.Printf("Last login updated for user_id: %s", loginData.UserId)
		}
	} else { // 패스워드 노일치
		log.Println("Password does not match.")

		success = false
		log.Printf("Failed login attempt for user_id: %s (invalid password)", loginData.UserId)

		response := viewm.LoginResponsetDto{
			Header: viewm.Header{
				Code:    "ERR",
				Message: "Incorrect password. Please try again.",
			},
		}
		c.JSON(http.StatusOK, response)

		setLoginFailedQuery := queries["set_login_failed"]
		params := map[string]interface{}{
			"user_id": loginData.UserId,
		}
		printQueryWithParams(setLoginFailedQuery, params)

		result, err := ctx.db.NamedExec(setLoginFailedQuery, params)
		if err != nil {
			log.Printf("Error updating login failed count for user_id: %s, error: %v", loginData.UserId, err)
			/*
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "Internal server error",
					"message": "Unable to update login failure information. Please try again later.",
				})
			*/
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			log.Printf("No updates made for login failure count: user_id %s might not exist", loginData.UserId)
			/*
				c.JSON(http.StatusNotFound, gin.H{
					"error":   "User not found",
					"message": "The specified user could not be found. Please check the user ID.",
				})
			*/
		} else {
			log.Printf("Successfully updated login failure count for user_id: %s", loginData.UserId)
			/*
				c.JSON(http.StatusOK, gin.H{
					"message": "Login failure information updated successfully.",
				})
			*/
		}
	}

	if success {
		loginRequests.WithLabelValues("success").Inc() // 성공 메트릭 증가
		//c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
	} else {
		loginRequests.WithLabelValues("failure").Inc() // 실패 메트릭 증가
		//c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
	}

	// 처리 시간 기록
	duration := time.Since(startTime).Seconds()
	loginDuration.WithLabelValues("/login").Observe(duration)
}

func protectedHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Welcome to the protected route!"})
}

func logoutHandler(c *gin.Context) {
	userID := c.GetString("user_id") // authMiddleware에서 설정한 사용자 ID 가져오기

	sessionKey := fmt.Sprintf("session:%s", userID) // redis key 삭제
	if _, err := ctx.rc.Del(context.Background(), sessionKey).Result(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete session key"})
		//return
	}

	activityKey := fmt.Sprintf("last_activity:%s", userID) // redis key 삭제
	if _, err := ctx.rc.Del(context.Background(), activityKey).Result(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete activity key"})
		//return
	}

	/*
		// 추후 blacklist token 관리 추가 예정(로그아웃 후에도 유효한 access token이 실린 요청을 명시적으로 차단하기 위함)
		blacklistKey := fmt.Sprintf("blacklist:%s:%s", userId, tokenString)
		if err := redisClient.Set(context.Background(), blacklistKey, "blacklisted", time.Until(time.Unix(int64(claims["exp"].(float64)), 0))).Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to blacklist token"})
			return
		}
	*/

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func healthCheckHandler(c *gin.Context) {
	checks := map[string]string{}

	// Gin 서버 상태 확인
	if c == nil { // Gin 서버 핸들러가 호출될 수 없는 경우
		checks["gin_server"] = "unreachable"
		c.JSON(http.StatusInternalServerError, gin.H{"status": "unhealthy", "details": checks})
		return
	} else {
		checks["gin_server"] = "running"
	}

	// Redis 체크
	if _, err := ctx.rc.Ping(context.Background()).Result(); err != nil {
		checks["redis"] = "down"
	} else {
		checks["redis"] = "connected"
	}

	// 데이터베이스 체크
	if err := ctx.db.Ping(); err != nil {
		checks["postgresql"] = "down"
	} else {
		checks["postgresql"] = "connected"
	}

	// 결과 반환
	for _, status := range checks {
		if status == "down" {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "unhealthy", "details": checks})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "healthy", "details": checks})
}

func gracefulShutdown(server *http.Server) {
	// 시스템 신호 수신 채널
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// SIGINT 또는 SIGTERM 신호를 기다림
	<-quit
	log.Println("Shutting down server...")

	/*
		if err := flushAllRedis(); err != nil {
			log.Printf("Failed to flush Redis: %v", err)
		}
	*/

	if err := deleteKeysRedis("session:", "rate_limiter:"); err != nil {
		log.Printf("Error deleting Redis keys: %v", err)
	}

	// 서버 종료 준비
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil { // 서버가 내려가면 프로메테우스 누적 내용은 자동으로 초기화
		log.Fatalf("Server forced to shutdown: %v\n", err)
	}

	log.Println("========== SERVER STOP ==========")
	log.Println("🛑 Server exiting")
	log.Println("=================================")
}

/*
// ===========================================
// Third Party
// ===========================================
*/

func authMiddleware() gin.HandlerFunc {
	/*
		// 프론트엔드(react + axios)에서 토큰 검증 요청 예시
		axios.get('/protected', {
			headers: {
				Authorization: `Bearer ${accessToken}`
			}
		})
	*/

	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return ctx.sk, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signature"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			}
			c.Abort()
			return
		}
		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func generateToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // HMAC-SHA256 알고리즘
	return token.SignedString(ctx.sk)                          // 추후 대칭 키 방식에서 비대칭 키 방식으로 전환 예정
}

func createRateLimiter(client *redis.Client) gin.HandlerFunc {
	// Redis 기반 스토어 생성
	store, err := redisstore.NewStoreWithOptions(client, limiter.StoreOptions{
		Prefix:   "rate_limiter",
		MaxRetry: 3,
	})
	if err != nil {
		log.Fatalf("Could not create store: %v", err)
	}

	// 속도 제한 정책 설정
	rate := limiter.Rate{
		Period: 1 * time.Second, // TTL: 1초
		Limit:  10,              // 1초 동안 최대 10개의 요청 허용
	}

	// 사용자 ID 및 IP 기반 키 생성
	return ginlimiter.NewMiddleware(
		limiter.New(store, rate),
		ginlimiter.WithKeyGetter(func(c *gin.Context) string {
			userID := c.GetHeader("Authorization")
			if userID == "" {
				userID = "anonymous"
			}
			return userID + ":" + c.ClientIP()
		}),
	)
}

func activityTimeoutMiddleware(c *gin.Context) {
	userID := c.GetString("user_id") // authMiddleware에서 설정된 사용자 ID 가져오기
	activityKey := fmt.Sprintf("last_activity:%s", userID)

	lastActivity, err := ctx.rc.Get(context.Background(), activityKey).Int64()
	if err != nil || time.Now().Unix()-lastActivity > 1800 { // 1800초(30분) 타임아웃
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session timed out"})
		c.Abort()
		return
	}

	ctx.rc.Set(context.Background(), activityKey, time.Now().Unix(), 0) // 마지막 활동 시간 갱신
	c.Next()
}

/*
// ===========================================
// Utilities
// ===========================================
*/

func hashPasswordAsync(password string, resultChan chan<- []byte, errorChan chan<- error) {
	go func() { // Goroutine(Thread) 비동기 실행
		hashedVl, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- hashedVl
	}()
}

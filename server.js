const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/static", express.static(path.join(__dirname, "static")));

const pool = mysql.createPool({
    host: "localhost",
    user: "testuser",
    password: "1234",
    database: "testdb",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const JWT_SECRET = "chungjeong_secret_key";

// -------------------- 페이지 라우트 --------------------

// 로그인 페이지
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "login.html"));
});

// 회원가입 페이지
app.get("/signup", (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "signup.html"));
});

// 로그인 실패 페이지
app.get("/login-fail", (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "login-fail.html"));
});

// 일반 사용자 메인 페이지
app.get("/user", (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "user.html"));
});

// 관리자 메인 페이지
app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "admin.html"));
});

// 기사 작성 페이지
app.get("/write", (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "write.html"));
});

// -------------------- 인증 관련 함수 --------------------

function verifyToken(req) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return null;
    }

    const token = authHeader.split(" ")[1];

    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// -------------------- 회원가입 API --------------------

app.post("/api/signup", async (req, res) => {
    try {
        const { user_id, password, user_name, role } = req.body;

        if (!user_id || !password || !user_name || !role) {
          return res.status(400).json({
              success: false,
              message: "모든 항목을 입력해야 합니다."
          });
        }

        if (role !== "user" && role !== "admin") {
            return res.status(400).json({
                success: false,
                message: "role은 user 또는 admin만 가능합니다."
            });
        }

        const [existingUsers] = await pool.execute(
            "SELECT id FROM users WHERE user_id = ?",
            [user_id]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: "이미 존재하는 아이디입니다."
            });
        }

        const hashed = await bcrypt.hash(password, 10);

        await pool.execute(
            "INSERT INTO users (user_id, password, user_name, role) VALUES (?, ?, ?, ?)",
            [user_id, hashed, user_name, role]
        );

        res.json({
            success: true,
            message: "회원가입이 완료되었습니다."
        });
    } catch (error) {
        console.error("회원가입 오류:", error);
        res.status(500).json({
            success: false,
            message: "회원가입 중 오류가 발생했습니다."
        });
    }
});

// -------------------- 로그인 API --------------------

app.post("/api/login", async (req, res) => {
    try {
        const { user_id, password } = req.body;

        if (!user_id || !password) {
          return res.status(400).json({
              success: false,
              message: "아이디와 비밀번호를 입력해야 합니다."
          });
        }

        const [rows] = await pool.execute(
            "SELECT * FROM users WHERE user_id = ?",
            [user_id]
        );

        if (rows.length === 0) {
            return res.json({
                success: false,
                message: "아이디 또는 비밀번호가 올바르지 않습니다."
            });
        }

        const user = rows[0];

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({
                success: false,
                message: "아이디 또는 비밀번호가 올바르지 않습니다."
            });
        }

        const token = jwt.sign(
          {
              id: user.id,
              user_id: user.user_id,
              user_name: user.user_name,
              role: user.role
          },
          JWT_SECRET,
          { expiresIn: "2h" }
        );

        res.json({
          success: true,
          message: "로그인 성공",
          token,
          role: user.role,
          user_name: user.user_name
        });
    } catch (error) {
        console.error("로그인 오류:", error);
        res.status(500).json({
            success: false,
            message: "로그인 중 오류가 발생했습니다."
        });
    }
});

// -------------------- 토큰 검증 API --------------------

app.get("/api/verify", async (req, res) => {
    const decoded = verifyToken(req);

    if (!decoded) {
        return res.status(401).json({
            success: false,
            message: "유효하지 않은 토큰입니다."
        });
    }

    res.json({
        success: true,
        user: decoded
    });
});

// -------------------- 기사 조회 API --------------------

app.get("/api/news", async (req, res) => {
    try {
        const [rows] = await pool.execute(
            "SELECT id, title, category, content, author FROM news ORDER BY id DESC"
        );

        res.json(rows);
    } catch (error) {
        console.error("기사 조회 오류:", error);
        res.status(500).json({
            success: false,
            message: "기사 조회 중 오류가 발생했습니다."
        });
    }
});

// -------------------- 기사 등록 API (관리자만 가능) --------------------

app.post("/api/news", async (req, res) => {
    try {
        const decoded = verifyToken(req);

        if (!decoded) {
            return res.status(401).json({
                success: false,
                message: "로그인이 필요합니다."
            });
        }

        if (decoded.role !== "admin") {
            return res.status(403).json({
                success: false,
                message: "관리자만 기사 등록이 가능합니다."
            });
        }

        const { title, category, content, author } = req.body;

        if (!title || !category || !content || !author) {
            return res.status(400).json({
                success: false,
                message: "모든 기사 항목을 입력해야 합니다."
            });
        }

        await pool.execute(
            "INSERT INTO news (title, category, content, author) VALUES (?, ?, ?, ?)",
            [title, category, content, author]
        );

        res.json({
            success: true,
            message: "기사 등록이 완료되었습니다."
        });
    } catch (error) {
        console.error("기사 등록 오류:", error);
        res.status(500).json({
            success: false,
            message: "기사 등록 중 오류가 발생했습니다."
        });
    }
});

app.listen(3000, () => {
    console.log("server running : http://localhost:3000");
});
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const SESSION_COOKIE = "login_session";
const SESSION_MAX_AGE = 60 * 60 * 1000;
const sessions = new Map();

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(derivedKey.toString("hex"));
    });
  });
}

async function readUsers() {
  try {
    return JSON.parse(await fs.readFile(USERS_FILE, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

async function writeUsers(users) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const temporaryFile = `${USERS_FILE}.tmp`;
  await fs.writeFile(temporaryFile, JSON.stringify(users, null, 2), "utf8");
  await fs.rename(temporaryFile, USERS_FILE);
}

function getSession(req) {
  const cookie = req.headers.cookie || "";
  const sessionCookie = cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE}=`));

  if (!sessionCookie) {
    return null;
  }

  const sessionId = sessionCookie.slice(SESSION_COOKIE.length + 1);
  const session = sessions.get(sessionId);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

function setSessionCookie(res, sessionId) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600${secure}`,
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
  );
}

function publicUser(user) {
  return { id: user.id, email: user.email };
}

app.post("/api/register", async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const email =
      typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return res.status(400).json({ message: "올바른 이메일 주소를 입력해 주세요." });
    }
    if (password.length < 8 || password.length > 128) {
      return res
        .status(400)
        .json({ message: "비밀번호는 8자 이상 128자 이하로 입력해 주세요." });
    }

    const users = await readUsers();
    if (users.some((user) => user.email === email)) {
      return res.status(409).json({ message: "이미 등록된 이메일입니다." });
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = await hashPassword(password, salt);
    const user = {
      id: crypto.randomUUID(),
      email,
      salt,
      passwordHash,
      createdAt: new Date().toISOString(),
    };
    users.push(user);
    await writeUsers(users);

    return res.status(201).json({
      message: "회원가입이 완료되었습니다. 로그인해 주세요.",
    });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const email =
      typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const users = await readUsers();
    const user = users.find((item) => item.email === email);

    if (!user) {
      return res.status(401).json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }
    const passwordHash = await hashPassword(password, user.salt);
    const passwordMatches = crypto.timingSafeEqual(
      Buffer.from(passwordHash, "hex"),
      Buffer.from(user.passwordHash, "hex"),
    );
    if (!passwordMatches) {
      return res.status(401).json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }

    const sessionId = crypto.randomBytes(32).toString("hex");
    sessions.set(sessionId, {
      userId: user.id,
      expiresAt: Date.now() + SESSION_MAX_AGE,
    });
    setSessionCookie(res, sessionId);
    return res.json({ message: "로그인되었습니다.", user: publicUser(user) });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/me", async (req, res, next) => {
  try {
    const session = getSession(req);
    if (!session) {
      return res.status(401).json({ message: "로그인이 필요합니다." });
    }
    const users = await readUsers();
    const user = users.find((item) => item.id === session.userId);
    if (!user) {
      return res.status(401).json({ message: "로그인이 필요합니다." });
    }
    return res.json({ user: publicUser(user) });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/logout", (req, res) => {
  const cookie = req.headers.cookie || "";
  const sessionCookie = cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  if (sessionCookie) {
    sessions.delete(sessionCookie.slice(SESSION_COOKIE.length + 1));
  }
  clearSessionCookie(res);
  res.json({ message: "로그아웃되었습니다." });
});

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) {
    return next(error);
  }
  return res.status(500).json({ message: "서버 오류가 발생했습니다." });
});

app.listen(PORT, () => {
  console.log(`로그인 서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
});

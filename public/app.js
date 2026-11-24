const authView = document.querySelector("#auth-view");
const accountView = document.querySelector("#account-view");
const form = document.querySelector("#auth-form");
const emailInput = document.querySelector("#email");
const passwordInput = document.querySelector("#password");
const message = document.querySelector("#message");
const submitButton = document.querySelector("#submit-button");
const loginTab = document.querySelector("#login-tab");
const registerTab = document.querySelector("#register-tab");
const accountEmail = document.querySelector("#account-email");
const logoutButton = document.querySelector("#logout-button");

let mode = "login";

function showMessage(text, success = false) {
  message.textContent = text;
  message.classList.toggle("success", success);
}

function setMode(nextMode) {
  mode = nextMode;
  const isLogin = mode === "login";
  loginTab.classList.toggle("active", isLogin);
  registerTab.classList.toggle("active", !isLogin);
  loginTab.setAttribute("aria-selected", String(isLogin));
  registerTab.setAttribute("aria-selected", String(!isLogin));
  submitButton.textContent = isLogin ? "로그인" : "회원가입";
  passwordInput.autocomplete = isLogin ? "current-password" : "new-password";
  showMessage("");
}

function showAccount(user) {
  authView.classList.add("hidden");
  accountView.classList.remove("hidden");
  accountEmail.textContent = user.email;
}

async function request(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.message || "요청을 처리하지 못했습니다.");
  }
  return result;
}

loginTab.addEventListener("click", () => setMode("login"));
registerTab.addEventListener("click", () => setMode("register"));

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  showMessage("");
  submitButton.disabled = true;

  try {
    const result = await request(`/api/${mode}`, {
      email: emailInput.value,
      password: passwordInput.value,
    });
    if (mode === "login") {
      showAccount(result.user);
      form.reset();
    } else {
      setMode("login");
      showMessage(result.message, true);
      passwordInput.value = "";
      emailInput.focus();
    }
  } catch (error) {
    showMessage(error.message);
  } finally {
    submitButton.disabled = false;
  }
});

logoutButton.addEventListener("click", async () => {
  logoutButton.disabled = true;
  try {
    await request("/api/logout", {});
    accountView.classList.add("hidden");
    authView.classList.remove("hidden");
    passwordInput.value = "";
    setMode("login");
  } catch (error) {
    showMessage(error.message);
  } finally {
    logoutButton.disabled = false;
  }
});

fetch("/api/me", { credentials: "same-origin" })
  .then(async (response) => {
    if (response.ok) {
      const result = await response.json();
      showAccount(result.user);
    }
  })
  .catch((error) => showMessage(`서버에 연결할 수 없습니다: ${error.message}`));

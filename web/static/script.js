document.addEventListener("DOMContentLoaded", function () {
    // Получаем элементы по ID и проверяем их существование
    const loginBtn = document.getElementById("loginBtn");
    const useUsbBtn = document.getElementById("useUsbBtn");
    const generateBtn = document.getElementById("generateBtn");
    const passwordDisplay = document.getElementById("passwordDisplay");
    const errorMessage = document.getElementById("errorMessage");
    const viewHistoryBtn = document.getElementById("viewHistoryBtn");

    // Обработчик для кнопки "Login" — проверка логина и пароля
    if (loginBtn) {
        loginBtn.addEventListener("click", async () => {
            const username = document.getElementById("username").value.trim();
            const password = document.getElementById("password").value.trim();

            // Отправка запроса для авторизации
            const res = await fetch("/api/authorize", {
                method: "POST",
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();

            if (data.authorized) {
                window.location.href = "/generate"; // Перенаправление на страницу генерации пароля
            } else {
                errorMessage.style.display = "block"; // Показываем сообщение об ошибке
            }
        });
    }

    // Обработчик для кнопки "Use USB for login" — авторизация через флешку
    if (useUsbBtn) {
        useUsbBtn.addEventListener("click", async () => {
            // Отправка запроса для авторизации через флешку
            const res = await fetch("/api/authorize", {
                method: "POST",
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: "", password: "" }) // Пустые поля для флешки
            });

            const data = await res.json();

            if (data.authorized) {
                window.location.href = "/generate"; // Перенаправление на страницу генерации пароля
            } else {
                errorMessage.style.display = "block"; // Показываем сообщение об ошибке
            }
        });
    }

    // Обработчик для кнопки "Generate Password"
    if (generateBtn) {
        generateBtn.addEventListener("click", async () => {
            // Отправка запроса на генерацию пароля
            const res = await fetch("/generate", {
                method: "POST",
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await res.json();

            if (data.password) {
                passwordDisplay.textContent = data.password; // Отображаем сгенерированный пароль
            } else {
                errorMessage.style.display = "block"; // Показываем ошибку, если не удалось сгенерировать пароль
            }
        });
    }

    // Обработчик для кнопки "View Password History"
    if (viewHistoryBtn) {
        viewHistoryBtn.addEventListener("click", () => {
            window.location.href = "/history"; // Перенаправление на страницу истории паролей
        });
    }

    // Обработчик для кнопки "Back to Generate Password" на странице истории
    const backToGenerateBtn = document.getElementById("backToGenerateBtn");
    if (backToGenerateBtn) {
        backToGenerateBtn.addEventListener("click", () => {
            window.location.href = "/generate"; // Перенаправление на страницу генерации паролей
        });
    }
    const generateTokenBtn = document.getElementById("generateTokenBtn");

if (generateTokenBtn) {
    generateTokenBtn.addEventListener("click", async () => {
        const res = await fetch("/api/token");
        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "access.token";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } else {
            alert("Failed to generate token.");
        }
    });
}

});

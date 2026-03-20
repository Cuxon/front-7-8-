# Практические занятия 7–8
## Фронтенд и бэкенд разработка | ИПТИП | 4 семестр 2025/2026

Серверное приложение на Node.js с аутентификацией через bcrypt и JWT, а также CRUD для товаров.

---

## Запуск

```bash
npm install
node index.js
```

Сервер: `http://localhost:3000`
Swagger UI: `http://localhost:3000/api-docs`

---

## Стек

- **Node.js** + **Express** — сервер
- **bcrypt** — хеширование паролей с солью (10 раундов)
- **jsonwebtoken** — выдача и валидация JWT (access-токен, TTL 15 минут)
- **nanoid** — генерация уникальных id
- **swagger-jsdoc** + **swagger-ui-express** — интерактивная документация API


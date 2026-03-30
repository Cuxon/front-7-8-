# Практические занятия 7–12 | Контрольная работа №2

Fullstack-приложение на Node.js/Express + React.
Реализованы: регистрация и вход с JWT, refresh-токены с ротацией, система ролей (RBAC), CRUD товаров и управление пользователями.

---

## Запуск

### Бэкенд

```bash
npm install
node index.js
```

- Сервер: `http://localhost:3000`
- Swagger UI: `http://localhost:3000/api-docs`

### Фронтенд

```bash
cd client
npm install
npm run dev
```

- Приложение: `http://localhost:5173`

> Фронтенд проксирует запросы `/api/*` на бэкенд автоматически через Vite.

---

## Стек

### Бэкенд
| Библиотека | Назначение |
|------------|------------|
| Express | HTTP-сервер и маршрутизация |
| bcrypt | Хеширование паролей (10 раундов соли) |
| jsonwebtoken | Генерация и валидация JWT |
| nanoid | Генерация уникальных id |
| swagger-jsdoc + swagger-ui-express | Интерактивная документация API |

### Фронтенд
| Библиотека | Назначение |
|------------|------------|
| React + Vite | SPA и инструмент сборки |
| React Router | Клиентская маршрутизация |
| Axios + interceptors | HTTP-клиент с автообновлением токенов |

---

## Архитектура токенов

- **Access-токен** — TTL 15 минут, передаётся в заголовке `Authorization: Bearer <token>`
- **Refresh-токен** — TTL 7 дней, передаётся в заголовке `x-refresh-token`
- При обновлении происходит **ротация**: старый refresh-токен удаляется из хранилища, клиент получает новую пару
- Повторное использование уже использованного refresh-токена → `401`
- Заблокированный пользователь не может войти и обновить токен → `403`

---

## Роли и права доступа

Три роли: `user` (просмотр), `seller` (управление товарами), `admin` (полный доступ).

| Маршрут | Метод | Гость | user | seller | admin |
|---------|-------|:-----:|:----:|:------:|:-----:|
| `/api/auth/register` | POST | ✓ | | | |
| `/api/auth/login` | POST | ✓ | | | |
| `/api/auth/refresh` | POST | ✓ | | | |
| `/api/auth/me` | GET | | ✓ | ✓ | ✓ |
| `/api/products` | GET | | ✓ | ✓ | ✓ |
| `/api/products/:id` | GET | | ✓ | ✓ | ✓ |
| `/api/products` | POST | | | ✓ | ✓ |
| `/api/products/:id` | PUT | | | ✓ | ✓ |
| `/api/products/:id` | DELETE | | | | ✓ |
| `/api/users` | GET | | | | ✓ |
| `/api/users/:id` | GET | | | | ✓ |
| `/api/users/:id` | PUT | | | | ✓ |
| `/api/users/:id` | DELETE | | | | ✓ |

> `DELETE /api/users/:id` не удаляет запись, а устанавливает `blocked: true`.

---

## Структура проекта

```
/
├── index.js          # Бэкенд: Express, JWT, RBAC, Swagger
├── package.json
└── client/           # Фронтенд: React + Vite
    └── src/
        ├── api/
        │   ├── client.js       # Axios + request/response interceptors
        │   ├── auth.js
        │   ├── products.js
        │   └── users.js
        ├── context/
        │   └── AuthContext.jsx # Глобальное состояние пользователя
        ├── components/
        │   ├── Navbar.jsx
        │   └── PrivateRoute.jsx
        └── pages/
            ├── Login.jsx
            ├── Register.jsx
            ├── Products.jsx
            ├── ProductDetail.jsx
            └── Users.jsx       # Только для admin
```

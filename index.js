const express = require('express');
const { nanoid } = require('nanoid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
const port = 3000;

const JWT_SECRET = 'access_secret';
const REFRESH_SECRET = 'refresh_secret';
const ACCESS_EXPIRES_IN = '15m';
const REFRESH_EXPIRES_IN = '7d';

const refreshTokens = new Set();

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API AUTH + PRODUCTS + USERS',
      version: '3.0.0',
      description: 'Практика 7–11 — аутентификация, JWT, refresh-токены, RBAC, товары и пользователи',
    },
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
    },
    servers: [{ url: `http://localhost:${port}`, description: 'Локальный сервер' }],
  },
  apis: ['./index.js'],
};

let users = [];
let products = [];

// ─── Helpers ────────────────────────────────────────────────────────────────

function findProductOrFail(id, res) {
  const product = products.find(p => p.id === id);
  if (!product) { res.status(404).json({ error: 'product not found' }); return null; }
  return product;
}

async function hashPassword(password) { return bcrypt.hash(password, 10); }
async function verifyPassword(password, hash) { return bcrypt.compare(password, hash); }

function safeUser(u) {
  return { id: u.id, email: u.email, first_name: u.first_name, last_name: u.last_name, role: u.role, blocked: u.blocked };
}

function generateAccessToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: ACCESS_EXPIRES_IN });
}

function generateRefreshToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES_IN });
}

// ─── Middleware ──────────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.find(u => u.id === payload.sub);
    if (user?.blocked) {
      return res.status(403).json({ error: 'Account is blocked' });
    }
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function roleMiddleware(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

// ─── Swagger + Express setup ─────────────────────────────────────────────────

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use(express.json());

app.use((req, res, next) => {
  res.on('finish', () => {
    console.log(`[${new Date().toISOString()}] [${req.method}] ${res.statusCode} ${req.path}`);
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) console.log('Body:', req.body);
  });
  next();
});

// ─── Auth routes ─────────────────────────────────────────────────────────────

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Регистрация пользователя
 *     description: Доступно гостям. Роль по умолчанию — user.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, first_name, last_name, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: ivan@example.com
 *               first_name:
 *                 type: string
 *                 example: Иван
 *               last_name:
 *                 type: string
 *                 example: Иванов
 *               password:
 *                 type: string
 *                 example: qwerty123
 *               role:
 *                 type: string
 *                 enum: [user, seller, admin]
 *                 example: user
 *     responses:
 *       201:
 *         description: Пользователь создан
 *       400:
 *         description: Некорректные данные
 *       409:
 *         description: Пользователь уже существует
 */
app.post('/api/auth/register', async (req, res) => {
  const { email, first_name, last_name, password, role } = req.body;

  if (!email || !first_name || !last_name || !password) {
    return res.status(400).json({ error: 'email, first_name, last_name and password are required' });
  }

  if (users.find(u => u.email === email)) {
    return res.status(409).json({ error: 'user already exists' });
  }

  const newUser = {
    id: nanoid(),
    email,
    first_name,
    last_name,
    password: await hashPassword(password),
    role: role || 'user',
    blocked: false,
  };

  users.push(newUser);
  res.status(201).json(safeUser(newUser));
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Вход в систему
 *     description: Доступно гостям. Возвращает пару access + refresh токенов.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: ivan@example.com
 *               password:
 *                 type: string
 *                 example: qwerty123
 *     responses:
 *       200:
 *         description: Успешная авторизация
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                 refreshToken:
 *                   type: string
 *       400:
 *         description: Отсутствуют обязательные поля
 *       401:
 *         description: Неверные учётные данные
 *       403:
 *         description: Аккаунт заблокирован
 */
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.blocked) return res.status(403).json({ error: 'Account is blocked' });

  const isAuthenticated = await verifyPassword(password, user.password);
  if (!isAuthenticated) return res.status(401).json({ error: 'Invalid credentials' });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  refreshTokens.add(refreshToken);

  res.status(200).json({ accessToken, refreshToken });
});

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Получить текущего пользователя
 *     description: Доступно пользователям, продавцам и администраторам.
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Данные текущего пользователя
 *       401:
 *         description: Не авторизован
 *       404:
 *         description: Пользователь не найден
 */
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'user not found' });
  res.status(200).json(safeUser(user));
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Обновление пары токенов
 *     description: Принимает refresh-токен из заголовка x-refresh-token, возвращает новую пару (ротация).
 *     tags: [Auth]
 *     parameters:
 *       - in: header
 *         name: x-refresh-token
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Новая пара токенов
 *       400:
 *         description: Заголовок отсутствует
 *       401:
 *         description: Токен недействителен или истёк
 *       403:
 *         description: Аккаунт заблокирован
 */
app.post('/api/auth/refresh', (req, res) => {
  const refreshToken = req.headers['x-refresh-token'];

  if (!refreshToken) {
    return res.status(400).json({ error: 'x-refresh-token header is required' });
  }
  if (!refreshTokens.has(refreshToken)) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  try {
    const payload = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = users.find(u => u.id === payload.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (user.blocked) return res.status(403).json({ error: 'Account is blocked' });

    refreshTokens.delete(refreshToken);
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    refreshTokens.add(newRefreshToken);

    res.status(200).json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// ─── Users routes (admin only) ───────────────────────────────────────────────

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Получить список пользователей
 *     description: Только администратор.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Список пользователей
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав (только admin)
 */
app.get('/api/users', authMiddleware, roleMiddleware(['admin']), (req, res) => {
  res.status(200).json(users.map(safeUser));
});

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Получить пользователя по id
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Данные пользователя
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав
 *       404:
 *         description: Пользователь не найден
 */
app.get('/api/users/:id', authMiddleware, roleMiddleware(['admin']), (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'user not found' });
  res.status(200).json(safeUser(user));
});

/**
 * @swagger
 * /api/users/{id}:
 *   put:
 *     summary: Обновить информацию пользователя
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               first_name:
 *                 type: string
 *               last_name:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [user, seller, admin]
 *     responses:
 *       200:
 *         description: Обновлённый пользователь
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав
 *       404:
 *         description: Пользователь не найден
 */
app.put('/api/users/:id', authMiddleware, roleMiddleware(['admin']), (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'user not found' });

  const { first_name, last_name, role } = req.body;
  if (first_name !== undefined) user.first_name = first_name;
  if (last_name !== undefined) user.last_name = last_name;
  if (role !== undefined) user.role = role;

  res.status(200).json(safeUser(user));
});

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Заблокировать пользователя
 *     description: Устанавливает blocked=true. Заблокированный пользователь не может войти в систему.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Пользователь заблокирован
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав
 *       404:
 *         description: Пользователь не найден
 */
app.delete('/api/users/:id', authMiddleware, roleMiddleware(['admin']), (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'user not found' });
  user.blocked = true;
  res.status(200).json(safeUser(user));
});

// ─── Products routes ─────────────────────────────────────────────────────────

/**
 * @swagger
 * /api/products:
 *   post:
 *     summary: Создать товар
 *     description: Доступно продавцам и администраторам.
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [title, category, description, price]
 *             properties:
 *               title:
 *                 type: string
 *                 example: Ноутбук
 *               category:
 *                 type: string
 *                 example: Электроника
 *               description:
 *                 type: string
 *                 example: Мощный ноутбук для работы
 *               price:
 *                 type: number
 *                 example: 75000
 *     responses:
 *       201:
 *         description: Товар создан
 *       400:
 *         description: Некорректные данные
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав (seller или admin)
 */
app.post('/api/products', authMiddleware, roleMiddleware(['seller', 'admin']), (req, res) => {
  const { title, category, description, price } = req.body;

  if (!title || !category || !description || price === undefined) {
    return res.status(400).json({ error: 'title, category, description and price are required' });
  }

  const newProduct = { id: nanoid(), title, category, description, price: Number(price) };
  products.push(newProduct);
  res.status(201).json(newProduct);
});

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Получить список товаров
 *     description: Доступно всем аутентифицированным пользователям.
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Список товаров
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав
 */
app.get('/api/products', authMiddleware, roleMiddleware(['user', 'seller', 'admin']), (req, res) => {
  res.status(200).json(products);
});

/**
 * @swagger
 * /api/products/{id}:
 *   get:
 *     summary: Получить товар по id
 *     description: Доступно всем аутентифицированным пользователям.
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Товар найден
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав
 *       404:
 *         description: Товар не найден
 */
app.get('/api/products/:id', authMiddleware, roleMiddleware(['user', 'seller', 'admin']), (req, res) => {
  const product = findProductOrFail(req.params.id, res);
  if (!product) return;
  res.status(200).json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   put:
 *     summary: Обновить параметры товара
 *     description: Доступно продавцам и администраторам.
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               category:
 *                 type: string
 *               description:
 *                 type: string
 *               price:
 *                 type: number
 *     responses:
 *       200:
 *         description: Товар обновлён
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав (seller или admin)
 *       404:
 *         description: Товар не найден
 */
app.put('/api/products/:id', authMiddleware, roleMiddleware(['seller', 'admin']), (req, res) => {
  const product = findProductOrFail(req.params.id, res);
  if (!product) return;

  const { title, category, description, price } = req.body;
  if (title !== undefined) product.title = title;
  if (category !== undefined) product.category = category;
  if (description !== undefined) product.description = description;
  if (price !== undefined) product.price = Number(price);

  res.status(200).json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   delete:
 *     summary: Удалить товар
 *     description: Только администратор.
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Товар удалён
 *       401:
 *         description: Не авторизован
 *       403:
 *         description: Нет прав (только admin)
 *       404:
 *         description: Товар не найден
 */
app.delete('/api/products/:id', authMiddleware, roleMiddleware(['admin']), (req, res) => {
  const index = products.findIndex(p => p.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'product not found' });
  res.status(200).json(products.splice(index, 1)[0]);
});

// ─── Start ───────────────────────────────────────────────────────────────────

app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
  console.log(`Swagger UI доступен по адресу http://localhost:${port}/api-docs`);
});

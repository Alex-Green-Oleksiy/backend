# Монорепозиторій Backend & Frontend Проектів

Цей репозиторій містить всі мої проекти для навчання React та розробки backend.

## 📁 Структура проекту

```
├── projects/
│   ├── backend/           # Backend проекти
│   │   ├── hospital-api/  # Hospital Management API
│   │   ├── project2/      # Майбутній проект
│   │   └── project3/      # Майбутній проект
│   └── frontend/          # Frontend проекти
│       ├── react-apps/    # React додатки
│       ├── project1/      # Майбутній React проект
│       └── project2/      # Майбутній React проект
├── README.md
└── .gitignore
```

## 🚀 Поточні проекти

### Backend
- **hospital-api** - Express.js сервер з API для управління лікарнями

### Frontend
- Поки що порожньо (React проекти будуть додані)

## 📋 Як додати новий проект

### Backend проект:
1. Створіть папку в `projects/backend/`
2. Ініціалізуйте Node.js проект: `npm init -y`
3. Встановіть залежності
4. Додайте README.md з описом проекту

### Frontend проект:
1. Створіть папку в `projects/frontend/`
2. Використайте Vite: `npm create vite@latest`
3. Налаштуйте проект
4. Додайте README.md з описом проекту

## 🌐 Деплой на Render.com

Для деплою окремого проекту на Render:
1. Створіть новий Web Service
2. Підключіть цей GitHub репозиторій
3. У налаштуваннях вкажіть:
   - **Root Directory**: `projects/backend/hospital-api` (або інший проект)
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`

## 📝 Примітки

- Кожен проект має свій `package.json` та залежності
- Використовуйте окремі порти для кожного проекту
- Документуйте кожен проект у його папці 
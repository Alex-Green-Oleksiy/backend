# Hospital Management API

Express.js сервер для управління лікарнями, лікарями, пацієнтами та призначеннями.

## 🚀 Запуск проекту

```bash
# Встановлення залежностей
npm install

# Запуск сервера
npm start

# Або в режимі розробки
npm run dev
```

## 📋 API Endpoints

### Лікарі (Doctors)
- `GET /api/doctors` - Отримати всіх лікарів
- `POST /api/doctors` - Створити нового лікаря
- `GET /api/doctors/:id` - Отримати лікаря за ID
- `PUT /api/doctors/:id` - Оновити лікаря
- `DELETE /api/doctors/:id` - Видалити лікаря

### Пацієнти (Patients)
- `GET /api/patients` - Отримати всіх пацієнтів
- `POST /api/patients` - Створити нового пацієнта
- `GET /api/patients/:id` - Отримати пацієнта за ID
- `PUT /api/patients/:id` - Оновити пацієнта
- `DELETE /api/patients/:id` - Видалити пацієнта

### Призначення (Appointments)
- `GET /api/appointments` - Отримати всі призначення
- `POST /api/appointments` - Створити нове призначення
- `GET /api/appointments/:id` - Отримати призначення за ID
- `PUT /api/appointments/:id` - Оновити призначення
- `DELETE /api/appointments/:id` - Видалити призначення

## 📁 Структура проекту

```
├── app.js              # Основний файл додатку
├── server.js           # Сервер
├── package.json        # Залежності
├── controllers/        # Контролери
│   ├── doctorsController.js
│   ├── patientsController.js
│   └── appointmentsController.js
├── routes/            # Маршрути
│   ├── doctors.js
│   ├── patients.js
│   └── appointments.js
├── data/              # JSON файли з даними
│   ├── doctors.json
│   ├── patients.json
│   └── appointments.json
└── utils/             # Утиліти
    └── fileHandler.js
```

## 🌐 Деплой на Render

Для деплою на Render.com:
1. Створіть новий Web Service
2. Підключіть GitHub репозиторій
3. Налаштування:
   - **Root Directory**: `projects/backend/current-project`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Port**: `3000`

## 📝 Примітки

- Дані зберігаються в JSON файлах
- API повертає JSON відповіді
- Всі endpoints підтримують CORS 
```
index.php
//////
<?php include 'inc/header.php'; ?>
<section>
	<!-- <img src="https://plus.unsplash.com/premium_photo-1678281888592-8ad623bb39e9" alt="Грузовик" width="300px"> -->

	<h2>Добро пожаловать на портал «Грузовозофф»</h2>
	<p>Мы предоставляем сервис онлайн-заказа грузоперевозок по России. Быстро, удобно, надёжно.</p>


	<?php if (!isset($_SESSION['user_id'])): ?>
		<p><a href="register.php">Зарегистрируйтесь</a> или <a href="login.php">войдите</a>, чтобы оставить заявку.</p>
	<?php else: ?>
		<p><a href="request_form.php">Оформить новую заявку</a> или <a href="profile.php">посмотреть мои заявки</a>.</p>
	<?php endif; ?>
</section>

<?php include 'inc/footer.php'; ?>///
////////
style.css
/* Базовые сбросы и глобальные стили */
* {
	margin: 0;
	padding: 0;
	box-sizing: border-box;
}

body {
	font-family: Arial, sans-serif;
	line-height: 1.6;
	background-color: #f4f4f4;
	color: #333;
	padding: 20px;
}

/* Шапка */
header {
	background: #2c3e50;
	color: white;
	padding: 20px 0;
	text-align: center;
	border-radius: 5px;
	margin-bottom: 20px;
}

h1 {
	font-size: 2.2rem;
	margin-bottom: 15px;
}

/* Навигация */
nav {
	background: #34495e;
	padding: 10px;
	border-radius: 5px;
}

nav a {
	color: white;
	text-decoration: none;
	margin: 0 10px;
	padding: 5px 10px;
	border-radius: 3px;
	transition: background 0.3s;
}

nav a:hover {
	background: #1abc9c;
}

/* Основной контент */
main {
	background: white;
	padding: 20px;
	border-radius: 5px;
	box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
}

/* Адаптивность */
@media (max-width: 600px) {
	nav {
		display: flex;
		flex-direction: column;
		gap: 5px;
	}

	nav a {
		margin: 2px 0;
		text-align: center;
	}
}
///////
request_form.php
<?php 
include 'inc/auth_check.php'; 
include 'inc/header.php'; 
?>

<h2>Оформить заявку</h2>
<form id="requestForm">
	<label>Дата и время перевозки: <input type="datetime-local" name="datetime" required></label><br>
	<label>Вес груза (кг): <input type="number" name="weight" required></label><br>
	<label>Габариты груза: <input type="text" name="dimensions" required></label><br>
	<label>Адрес отправления: <input type="text" name="from_address" required></label><br>
	<label>Адрес доставки: <input type="text" name="to_address" required></label><br>
	<label>Тип груза:
		<select name="cargo_type" required>
			<option value="">-- выберите --</option>
			<option>хрупкое</option>
			<option>скоропортящееся</option>
			<option>требуется рефрижератор</option>
			<option>животные</option>
			<option>жидкость</option>
			<option>мебель</option>
			<option>мусор</option>
		</select>
	</label><br>
	<button type="submit">Отправить заявку</button>
</form>

<div id="requestMessage"></div>

<script>
document.getElementById('requestForm').addEventListener('submit', async function(e) {
	e.preventDefault();
	const formData = new FormData(this);
	const jsonData = JSON.stringify(Object.fromEntries(formData));

	const response = await fetch('api/submit_request.php', {
		method: 'POST',
		body: jsonData
	});

	const result = await response.json();
	document.getElementById('requestMessage').innerText = result.message;

	if (result.status === 'success') {
		setTimeout(() => window.location.href = 'profile.php', 1000);
	}
});
</script>

<?php include 'inc/footer.php'; ?>
///////////
register.php
<?php
// Используем абсолютный путь к файлу подключения
include __DIR__ . '/connect.php';
include 'inc/header.php';

// Обработка регистрации
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$fio = $_POST['fio'] ?? '';
	$phone = $_POST['phone'] ?? '';
	$email = $_POST['email'] ?? '';
	$login = $_POST['login'] ?? '';
	$password = $_POST['password'] ?? '';

	// Блокировка регистрации администратора
	if ($login === 'admin') {
		$error = 'Логин "admin" зарезервирован';
	} else {
		// Проверка уникальности логина
		$stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE login = ?");
		$stmt->execute([$login]);
		$loginExists = $stmt->fetchColumn() > 0;

		// Проверка уникальности email
		$stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
		$stmt->execute([$email]);
		$emailExists = $stmt->fetchColumn() > 0;

		if ($loginExists) {
			$error = 'Пользователь с таким логином уже существует';
		} elseif ($emailExists) {
			$error = 'Пользователь с таким email уже существует';
		} else {
			// Хеширование пароля
			$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

			// Вставка в БД
			$stmt = $pdo->prepare("INSERT INTO users (fio, phone, email, login, password) VALUES (?, ?, ?, ?, ?)");
			$stmt->execute([$fio, $phone, $email, $login, $hashedPassword]);

			$success = 'Регистрация успешна!';
			echo '<meta http-equiv="refresh" content="2;url=login.php">';
		}
	}
}
?>

<h2>Регистрация</h2>

<?php if ($error): ?>
	<div style="color: red; padding: 10px; border: 1px solid red; margin: 10px 0; text-align: center;">
		<?= $error ?>
	</div>
<?php endif; ?>

<?php if ($success): ?>
	<div style="color: green; padding: 10px; border: 1px solid green; margin: 10px 0; text-align: center;">
		<?= $success ?>
	</div>
<?php endif; ?>

<form method="POST">
	<label>ФИО: <input type="text" name="fio" required></label><br>
	<label>Телефон: <input type="text" name="phone" placeholder="+7(123)-456-78-90" required></label><br>
	<label>Email: <input type="email" name="email" required></label><br>
	<label>Логин: <input type="text" name="login" required></label><br>
	<label>Пароль: <input type="password" name="password" required></label><br>
	<button type="submit">Зарегистрироваться</button>
</form>

<?php include 'inc/footer.php'; ?>
//////////
profile.php
<?php
include 'inc/auth_check.php';
include 'inc/header.php';
require_once 'connect.php';

$stmt = $pdo->prepare("SELECT * FROM requests WHERE user_id = ?");
$stmt->execute([$_SESSION['user_id']]);
$requests = $stmt->fetchAll();
?>

<h2>Мои заявки</h2>

<?php if ($requests): ?>
	<ul>
		<?php foreach ($requests as $req): ?>
			<li>
				<?= htmlspecialchars($req['datetime']) ?> —
				<?= htmlspecialchars($req['cargo_type']) ?> —
				<?= htmlspecialchars($req['from_address']) ?> → <?= htmlspecialchars($req['to_address']) ?>
				<strong>[<?= $req['status'] ?>]</strong>
			</li>
		<?php endforeach; ?>
	</ul>
<?php else: ?>
	<p>У вас нет заявок.</p>
<?php endif; ?>

<p><a href="request_form.php">Оформить новую заявку</a></p>

<?php include 'inc/footer.php'; ?>
///////////
logout.php
<?php
session_start();
session_unset();
session_destroy();
header("Location: index.php");
exit;
///////////
login.php
<?php
// Используем абсолютный путь к файлу подключения
include __DIR__ . '/connect.php';
include 'inc/header.php';

// Обработка входа
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$login = $_POST['login'] ?? '';
	$password = $_POST['password'] ?? '';

	// Проверка администратора
	if ($login === 'admin' && $password === 'gruzovik2024') {
		$_SESSION['user_id'] = 1;
		$_SESSION['is_admin'] = true;
		header('Location: profile.php');
		exit;
	}
	// Проверка обычных пользователей
	else {
		$stmt = $pdo->prepare("SELECT id, password FROM users WHERE login = ?");
		$stmt->execute([$login]);
		$user = $stmt->fetch();

		if ($user && password_verify($password, $user['password'])) {
			$_SESSION['user_id'] = $user['id'];
			$_SESSION['is_admin'] = false;
			header('Location: profile.php');
			exit;
		} else {
			$error = 'Неверные учетные данные';
		}
	}
}
?>

<h2>Вход</h2>

<?php if (!empty($error)): ?>
	<div style="color: red; padding: 10px; border: 1px solid red; margin: 10px 0; text-align: center;">
		<?= $error ?>
	</div>
<?php endif; ?>

<form method="POST">
	<label>Логин: <input type="text" name="login" required></label><br>
	<label>Пароль: <input type="password" name="password" required></label><br>
	<button type="submit">Войти</button>
</form>

<?php include 'inc/footer.php'; ?>
///////
connect.php
<?php
$host = 'localhost:3307';
$db   = 'gruzovik_db';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Ошибка подключения к базе данных']);
    exit;
}
//////////
admin.php
<?php
session_start();
include 'inc/header.php';
require_once 'connect.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
	echo "<p>Доступ запрещен. Только для администратора.</p>";
	include 'inc/footer.php';
	exit;
}

// Обновление статуса заявки
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['request_id'], $_POST['status'])) {
	$stmt = $pdo->prepare("UPDATE requests SET status = ? WHERE id = ?");
	$stmt->execute([$_POST['status'], $_POST['request_id']]);
}

// Получение всех заявок
$stmt = $pdo->query("SELECT r.*, u.fio FROM requests r JOIN users u ON r.user_id = u.id ORDER BY r.datetime DESC");
$requests = $stmt->fetchAll();
?>

<h2>Панель администратора</h2>

<?php if ($requests): ?>
	<table border="1" cellpadding="8">
		<tr>
			<th>ID</th>
			<th>ФИО пользователя</th>
			<th>Дата и время</th>
			<th>Тип груза</th>
			<th>Откуда → Куда</th>
			<th>Вес, габариты</th>
			<th>Статус</th>
			<th>Действия</th>
		</tr>
		<?php foreach ($requests as $req): ?>
			<tr>
				<td><?= $req['id'] ?></td>
				<td><?= htmlspecialchars($req['fio']) ?></td>
				<td><?= $req['datetime'] ?></td>
				<td><?= $req['cargo_type'] ?></td>
				<td><?= $req['from_address'] ?> → <?= $req['to_address'] ?></td>
				<td><?= $req['cargo_weight'] ?> кг, <?= $req['dimensions'] ?></td>
				<td><strong><?= $req['status'] ?></strong></td>
				<td>
					<form method="POST">
						<input type="hidden" name="request_id" value="<?= $req['id'] ?>">
						<select name="status">
							<option value="Новая" <?= $req['status'] == 'Новая' ? 'selected' : '' ?>>Новая</option>
							<option value="В работе" <?= $req['status'] == 'В работе' ? 'selected' : '' ?>>В работе</option>
							<option value="Отменена" <?= $req['status'] == 'Отменена' ? 'selected' : '' ?>>Отменена</option>
						</select>
						<button type="submit">Изменить</button>
					</form>
				</td>
			</tr>
		<?php endforeach; ?>
	</table>
<?php else: ?>
	<p>Заявок пока нет.</p>
<?php endif; ?>

<?php include 'inc/footer.php'; ?>
/////////////////

Создаём папку inc и в неё 3 файла

header.php
<?php
if (session_status() === PHP_SESSION_NONE) {
	session_start();
}
?>
<!DOCTYPE html>
<html lang="ru">

<head>
	<meta charset="UTF-8">
	<title>Грузоперевозки</title>
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="stylesheet" href="style.css">
</head>

<body>
	<header>
		<h1>Сервис грузоперевозок</h1>
		<nav>
			<a href="index.php">Главная</a>
			<?php if (!empty($_SESSION['user_id'])): ?>
				<a href="profile.php">Профиль</a>
				<?php if (!empty($_SESSION['is_admin'])): ?>
					<a href="admin.php">Админ-панель</a>
				<?php endif; ?>
				<a href="logout.php">Выход</a>
			<?php else: ?>
				<a href="login.php">Вход</a>
				<a href="register.php">Регистрация</a>
			<?php endif; ?>
		</nav>
	</header>
	<main>
///////////
footer.php
</main>
<footer>
	<p>&copy; <?= date("Y") ?> Грузоперевозки</p>
</footer>
</body>

</html>
/////////////
auth_check.php
<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}
///////////////
Создаём папку api и в неё 3 файла
submit_request.php
<?php
header('Content-Type: application/json');
session_start();

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['status' => 'error', 'message' => 'Не авторизован']);
    exit;
}

require_once '../connect.php';

$data = json_decode(file_get_contents("php://input"), true);

$stmt = $pdo->prepare("INSERT INTO requests (user_id, cargo_type, cargo_weight, dimensions, from_address, to_address, datetime) 
    VALUES (?, ?, ?, ?, ?, ?, ?)");

$stmt->execute([
    $_SESSION['user_id'],
    $data['cargo_type'],
    $data['weight'],
    $data['dimensions'],
    $data['from_address'],
    $data['to_address'],
    $data['datetime']
]);

echo json_encode(['status' => 'success', 'message' => 'Заявка отправлена на рассмотрение']);
///////////////////
register.php
<?php
header('Content-Type: application/json');
require_once '../db/connect.php';

// Получение данных из POST
$data = json_decode(file_get_contents("php://input"), true);

// Валидация данных
$errors = [];

if (!preg_match('/^[а-яА-ЯёЁ\s]+$/u', $data['fio'] ?? '')) {
    $errors[] = 'Некорректное ФИО';
}
if (!preg_match('/^\+7\(\d{3}\)-\d{3}-\d{2}-\d{2}$/', $data['phone'] ?? '')) {
    $errors[] = 'Некорректный номер телефона';
}
if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Некорректный email';
}
if (!preg_match('/^[а-яА-ЯёЁ0-9]{6,}$/u', $data['login'] ?? '')) {
    $errors[] = 'Логин должен быть на кириллице и не короче 6 символов';
}
if (strlen($data['password'] ?? '') < 6) {
    $errors[] = 'Пароль должен быть не менее 6 символов';
}

if ($errors) {
    echo json_encode(['status' => 'error', 'messages' => $errors]);
    exit;
}

// Проверка уникальности логина
$stmt = $pdo->prepare("SELECT id FROM users WHERE login = ?");
$stmt->execute([$data['login']]);
if ($stmt->fetch()) {
    echo json_encode(['status' => 'error', 'messages' => ['Логин уже используется']]);
    exit;
}

// Хеширование пароля и вставка
$hash = password_hash($data['password'], PASSWORD_DEFAULT);

$stmt = $pdo->prepare("INSERT INTO users (fio, phone, email, login, password) VALUES (?, ?, ?, ?, ?)");
$stmt->execute([
    $data['fio'],
    $data['phone'],
    $data['email'],
    $data['login'],
    $hash
]);

echo json_encode(['status' => 'success', 'message' => 'Регистрация прошла успешно']);
///////////////////////
login.php
<?php
header('Content-Type: application/json');
require_once '../db/connect.php';

$data = json_decode(file_get_contents("php://input"), true);

$login = $data['login'] ?? '';
$password = $data['password'] ?? '';

if (!$login || !$password) {
    echo json_encode(['status' => 'error', 'message' => 'Введите логин и пароль']);
    exit;
}

$stmt = $pdo->prepare("SELECT * FROM users WHERE login = ?");
$stmt->execute([$login]);
$user = $stmt->fetch();

if (!$user || !password_verify($password, $user['password'])) {
    echo json_encode(['status' => 'error', 'message' => 'Неверный логин или пароль']);
    exit;
}

session_start();
$_SESSION['user_id'] = $user['id'];
$_SESSION['is_admin'] = ($user['login'] === 'admin');

echo json_encode(['status' => 'success', 'message' => 'Авторизация успешна']);
```

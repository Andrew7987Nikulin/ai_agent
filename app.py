from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from sqlalchemy import text
import os
import logging
import json
import uuid
import requests
import time
import chromedriver_autoinstaller
import re
from datetime import datetime
import pyotp
import qrcode
from io import BytesIO
import base64

# Инициализация Flask
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-secret-key-here'  # Замените на надежный секретный ключ

# Инициализация расширений
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    totp_secret = db.Column(db.String(32), nullable=True)  # Поле для секрета TOTP

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()

    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email, issuer_name='GPT-4o Browser Automation'
        )

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Создание таблиц БД
with app.app_context():
    db.create_all()

with app.app_context():
    # Проверяем список столбцов таблицы 'user'
    with db.engine.connect() as connection:
        result = connection.execute(text("PRAGMA table_info(user)")).fetchall()
        columns = [row[1] for row in result]  # Извлекаем имена столбцов (row[1] — имя столбца)

    # Проверяем, отсутствует ли 'totp_secret'
    if 'totp_secret' not in columns:
        # Добавляем столбец 'totp_secret' типа TEXT
        with db.engine.connect() as connection:
            connection.execute(text("ALTER TABLE user ADD COLUMN totp_secret TEXT"))
            connection.commit()  # Фиксируем изменения

# Конфигурация API GPT‑4o и 2Captcha
API_URL = "https://api.proxyapi.ru/openai/v1/chat/completions"
API_KEY = "secret"
CAPTCHA_API_KEY = "secret"
CAPTCHA_URL = "https://2captcha.com/in.php"
CAPTCHA_RESULT_URL = "https://2captcha.com/res.php"

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def is_captcha_present(driver):
    """
    Проверяет, есть ли на странице капча, используя ключевые слова и селекторы.
    """
    try:
        captcha_keywords = [
            "captcha", "решите капчу", "докажите, что вы не робот",
            "введите символы", "я не робот"
        ]
        page_text = driver.page_source.lower()
        if any(keyword in page_text for keyword in captcha_keywords):
            logger.info("Капча обнаружена по текстовому маркеру.")
            return True

        captcha_selectors = [
            'img[src*="captcha"]',
            'input[name*="captcha"]',
            'div.captcha',
            'iframe[src*="captcha"]',
            'div.recaptcha',
            'div.g-recaptcha',
        ]
        for selector in captcha_selectors:
            try:
                WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                )
                logger.info(f"Капча обнаружена по селектору: {selector}")
                return True
            except Exception:
                continue
        logger.info("Капча не обнаружена.")
        return False
    except Exception as e:
        logger.error(f"Ошибка при проверке капчи: {str(e)}")
        return False


def send_captcha_to_2captcha(image_path):
    with open(image_path, "rb") as image_file:
        response = requests.post(
            CAPTCHA_URL,
            files={"file": image_file},
            data={"key": CAPTCHA_API_KEY, "method": "post"}
        )
    if response.ok and response.text.startswith("OK|"):
        captcha_id = response.text.split("|")[1]
        logger.info(f"Капча отправлена в 2Captcha. ID задачи: {captcha_id}")
        return captcha_id
    else:
        logger.error(f"Ошибка при отправке капчи: {response.text}")
        return None


def get_captcha_solution(captcha_id):
    params = {
        "key": CAPTCHA_API_KEY,
        "action": "get",
        "id": captcha_id
    }
    while True:
        response = requests.get(CAPTCHA_RESULT_URL, params=params)
        if response.text == "CAPCHA_NOT_READY":
            logger.info("Решение капчи еще не готово. Ожидание...")
            time.sleep(5)
        elif response.text.startswith("OK|"):
            solution = response.text.split("|")[1]
            logger.info(f"Решение капчи получено: {solution}")
            return solution
        else:
            logger.error(f"Ошибка при получении решения: {response.text}")
            return None


def solve_captcha(driver):
    try:
        captcha_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"captcha_{uuid.uuid4()}.png")
        driver.save_screenshot(captcha_image_path)
        logger.info(f"Скриншот капчи сохранен: {captcha_image_path}")
        captcha_id = send_captcha_to_2captcha(captcha_image_path)
        if not captcha_id:
            return False
        solution = get_captcha_solution(captcha_id)
        if not solution:
            return False
        captcha_input = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, 'input[name*="captcha"], input[id*="captcha"]'))
        )
        captcha_input.clear()
        captcha_input.send_keys(solution)
        logger.info(f"Решение капчи введено: {solution}")
        submit_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]'))
        )
        submit_button.click()
        logger.info("Кнопка отправки нажата.")
        WebDriverWait(driver, 30).until(
            EC.invisibility_of_element_located((By.CSS_SELECTOR, 'img[src*="captcha"]'))
        )
        logger.info("Капча решена.")
        return True
    except Exception as e:
        logger.error(f"Ошибка при решении капчи: {str(e)}")
        return False


def click_submit_button(driver):
    """
    Альтернативный способ отправки: находим поле ввода,
    устанавливаем фокус через JavaScript и имитируем нажатие Enter.
    """
    try:
        input_field = find_input_field(driver, None)
        if input_field:
            driver.execute_script("arguments[0].scrollIntoView(true); arguments[0].focus();", input_field)
            input_field.send_keys(Keys.ENTER)
            logger.info("Нажата клавиша Enter для отправки запроса.")
            return True
        else:
            logger.error("Не найдено поле ввода для имитации нажатия Enter.")
            return False
    except Exception as e:
        logger.error(f"Ошибка при имитации нажатия Enter: {str(e)}")
        return False


def find_input_field(driver, selector):
    """
    Универсальная функция для поиска поля ввода.
    Если селектор задан – ищется по нему, иначе перебираются распространенные варианты.
    Фокус устанавливается через JavaScript.
    """
    element = None
    if selector:
        try:
            element = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, selector))
            )
        except Exception as e:
            logger.warning(f"Элемент по селектору {selector} не найден: {str(e)}")
    if not element:
        common_selectors = [
            "textarea[aria-label='Введите поисковый запрос']",  # новое поле Bing
            "input[aria-label='Поиск']",
            "input[type='text']",
            "textarea",
            "input:not([type])",
            "input[placeholder*='поиск']",
            "input[placeholder*='Search']",
            "input[name='q']",
            "input#searchInput[placeholder='Найти на Wildberries']"
        ]
        for sel in common_selectors:
            try:
                element = WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, sel))
                )
                logger.info(f"Поле ввода найдено по селектору: {sel}")
                break
            except Exception as e:
                logger.debug(f"Не найдено по {sel}: {str(e)}")
                continue
    if element:
        try:
            driver.execute_script("arguments[0].focus();", element)
        except Exception as e:
            logger.debug(f"Ошибка установки фокуса через JavaScript: {str(e)}")
        return element
    logger.error("Не удалось найти поле ввода ни по одному из селекторов.")
    return None


def get_gpt4o_response(prompt):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    system_message = '''You are a browser automation assistant. Return JSON instructions for Selenium for various types of queries.
If the query is a general search (e.g. "самая популярная машина в 2025 году"), then:
  1. Open Bing (https://www.bing.com).
  2. Type the query into the search box.
  3. Instead of clicking a submit button, simulate Enter key press.
  4. Analyze the search results to identify the most informative page.
  5. Open that page.
  6. Extract a concise summary and the page URL.
  7. Return the result in a "return_text" action with keys "text" and "url".
  
If the query is "найди товар x на wildberries":
  1. Construct the URL: https://www.wildberries.ru/catalog/0/search.aspx?search=<x> replacing spaces with %20.
  2. Open the URL using "open_url".
  3. Return a "return_text" action with text "Результаты поиска 'x' на Wildberries" and the URL.

If the query is "найди товар x":
  - If the user specifies a site, then:
      1. Open the specified website.
      2. Search for the product by typing the text followed by Enter.
      3. Return the first product's link and a brief description in a "return_text" action.
  - If no site is specified:
      1. Open Bing.
      2. Search for "товар x" by typing the text followed by Enter.
      3. Analyze the results to find a marketplace website.
      4. Open that website, then search for the product.
      5. Return the first product's link and a brief description using "return_text".

If the query is "найди номер" followed by a hotel or отель name:
  1. Open booking.com.
  2. Type the hotel/отель name into the search field followed by Enter.
  3. Return the link of the first hotel in the list along with a concise description using "return_text".

Available actions:
  - open_url (with "url" parameter)
  - type_text (with "selector" and "text" parameters)
  - click_element (with "selector" parameter, if needed)
  - take_screenshot (with "filename" parameter) [only perform if explicitly requested]
  - return_text (with "text" and optionally "url" parameters)
  - close_window (this action will close the browser window if requested)

Return only ONE 'type_text' action per input field. 
Avoid duplicate actions. Use 'Enter' simulation instead of separate 'click_element' for submission.

Return the result strictly in JSON in the following structure:
{
    "actions": [
        {"action": "action_name", ...},
         ...
    ]
}
Do not include any extraneous text in your output.'''
    data = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt}
        ],
        "response_format": {"type": "json_object"}
    }
    try:
        logger.info(f"Sending request to GPT-4o API with prompt: {prompt}")
        response = requests.post(API_URL, headers=headers, json=data)
        logger.info(f"API response status: {response.status_code}")
        logger.info(f"API response text: {response.text}")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"API Error: {str(e)}")
        return None


def init_driver(browser):
    """Инициализация драйвера с автоматической установкой chromedriver"""
    try:
        if browser == "chrome":
            # Автоматическая установка/обновление ChromeDriver
            chromedriver_autoinstaller.install()

            # Настройка опций Chrome
            chrome_options = ChromeOptions()
            chrome_options.add_experimental_option("detach", True)

            # Инициализация драйвера
            driver = webdriver.Chrome(options=chrome_options)
            logger.info("ChromeDriver успешно инициализирован")
            return driver

        elif browser == "firefox":
            service = FirefoxService(GeckoDriverManager().install())
            return webdriver.Firefox(service=service)

        elif browser == "edge":
            service = EdgeService(EdgeChromiumDriverManager().install())
            return webdriver.Edge(service=service)

        else:
            raise ValueError("Неподдерживаемый браузер")

    except Exception as e:
        logger.error(f"Ошибка инициализации драйвера: {str(e)}")
        raise


def execute_actions(actions, browser):
    driver = None
    result = {'status': 'success', 'screenshots': [], 'found_captchas': []}

    try:
        driver = init_driver(browser)
        initial_url = driver.current_url  # Запоминаем стартовый URL

        for action in actions:
            # Пропускаем действия если уже есть ошибка
            if result['status'].startswith('error'):
                break

            if action['action'] == 'open_url':
                driver.get(action['url'])
                # Улучшенное ожидание загрузки
                WebDriverWait(driver, 30).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                              and len(d.find_elements(By.TAG_NAME, "body")) > 0
                )
                if is_captcha_present(driver):
                    logger.info("Капча обнаружена. Попытка решения...")
                    if not solve_captcha(driver):
                        result['status'] = 'error: Не удалось решить капчу'
                        return result

            elif action['action'] == 'type_text':
                try:
                    # Поиск поля ввода с повторными попытками
                    input_field = WebDriverWait(driver, 20).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, action.get(
                            'selector') or 'textarea[aria-label="Введите поисковый запрос"]'))
                    )

                    # Очистка и ввод текста
                    input_field.clear()
                    input_field.send_keys(action['text'])

                    # Отправка через Enter с ожиданием изменения
                    input_field.send_keys(Keys.ENTER)

                    # Специфичное ожидание для Bing
                    WebDriverWait(driver, 30).until(
                        lambda d: "search?q=" in d.current_url  # Проверка поисковой выдачи
                                  and len(d.find_elements(By.CSS_SELECTOR, "li.b_algo")) >= 3  # Минимум 3 результата
                    )

                except Exception as e:
                    logger.error(f"Ошибка ввода: {str(e)}")
                    result['status'] = f'error: {str(e)}'

            elif action['action'] == 'click_element':
                if action.get('use_enter', False):
                    if not click_submit_button(driver):
                        result['status'] = 'error: Не удалось отправить запрос через нажатие Enter'
                        return result
                else:
                    element = WebDriverWait(driver, 10).until(
                        EC.element_to_be_clickable((By.CSS_SELECTOR, action['selector']))
                    )
                    driver.execute_script("arguments[0].scrollIntoView(true);", element)
                    element.click()
                    logger.info(f"Клик выполнен по элементу: {action['selector']}")

            elif action['action'] == 'type_text':
                input_field = find_input_field(driver, action.get('selector'))
                if input_field:
                    input_field.clear()
                    input_field.send_keys(action['text'])
                    input_field.send_keys(Keys.ENTER)
                    logger.info(f"Текст отправлен через Enter")
                    WebDriverWait(driver, 15).until(EC.url_changes(driver.current_url))
                else:
                    result['status'] = "error: Поле ввода не найдено"
                    return result

            elif action['action'] == 'take_screenshot':
                filename = action['filename']
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                driver.save_screenshot(path)
                result['screenshots'].append(filename)
                logger.info(f"Скриншот сохранен: {filename}")

            elif action['action'] == 'return_text':
                result['text'] = action.get('text', '')
                if 'url' in action:
                    result['url'] = action['url']
                logger.info("Возвращён текстовый результат из действия return_text.")

            elif action['action'] == 'close_window':
                logger.info("Действие close_window получено, но окно останется открытым.")
                result['status'] = "success: Окно остается открытым"
                driver_closed_by_action = True

            else:
                logger.error(f"Неизвестное действие: {action['action']}")
                result['status'] = f"error: Неизвестное действие: {action['action']}"
                return result

        # Фолбэк для Amazon: если в result нет текста или ссылки, пробуем извлечь данные
        if driver and not driver_closed_by_action and not (result.get("text") or result.get("url")):
            current_url = driver.current_url.lower()
            if "amazon.com" in current_url:
                try:
                    first_product = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, "div.s-result-item"))
                    )
                    link_element = first_product.find_element(By.CSS_SELECTOR, "a.a-link-normal")
                    product_link = link_element.get_attribute("href")
                    product_description = link_element.text.strip()
                    result["text"] = product_description if product_description else "Описание не найдено"
                    result["url"] = product_link
                    logger.info("Извлечены данные с Amazon: ссылка и краткое описание.")
                except Exception as ex:
                    logger.error("Ошибка при извлечении данных с Amazon: " + str(ex))

    except Exception as e:
        result['status'] = f'error: {str(e)}'
    finally:
        # В данном случае окно браузера остаётся открытым (detach=True)
        pass

    return result


# Маршруты аутентификации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return render_template('auth.html', mode='register', error='Некорректный формат email')

        if User.query.filter_by(email=email).first():
            return render_template('auth.html', mode='register', error='Пользователь с таким email уже существует')

        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('index'))

    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    show_2fa = False
    error = None

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            error = 'Неверный email или пароль'
        elif user.totp_secret:
            token = request.form.get('token')
            if not token or not user.verify_totp(token):
                error = 'Неверный код 2FA'
            else:
                login_user(user)
                return redirect(url_for('index'))
        else:
            login_user(user)
            return redirect(url_for('index'))

        # Если есть ошибка и пользователь с 2FA, показываем поле 2FA
        if user and user.totp_secret:
            show_2fa = True

    return render_template('auth.html', mode='login', error=error, show_2fa=show_2fa)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if current_user.totp_secret:
        flash('Двухфакторная аутентификация уже включена.', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        token = request.form.get('token')
        if current_user.verify_totp(token):
            db.session.commit()
            flash('2FA успешно включена!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный код подтверждения.', 'error')
            return redirect(url_for('enable_2fa'))

    current_user.generate_totp_secret()
    db.session.commit()

    totp_uri = current_user.get_totp_uri()
    qr = qrcode.make(totp_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode()

    return render_template('enable_2fa.html', qr_code=qr_code)

# Основные маршруты
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/execute', methods=['POST'])
@login_required
def execute_task():
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error: No JSON data provided'}), 400

    prompt = data.get('prompt')
    browser = data.get('browser', 'chrome')
    if not prompt:
        return jsonify({'status': 'error: Prompt is required'}), 400

    try:
        gpt_response = get_gpt4o_response(prompt)
        content = json.loads(gpt_response['choices'][0]['message']['content'])
        actions = content.get('actions', [])

        unique_actions = []
        seen_actions = set()
        for action in actions:
            action_hash = frozenset(action.items())
            if action_hash not in seen_actions:
                unique_actions.append(action)
                seen_actions.add(action_hash)

        result = execute_actions(unique_actions, browser)

        if result['status'] == 'success':
            result['status'] = "Возможный результат уже открыт в отдельной вкладке."

        return jsonify(result)

    except Exception as e:
        logger.error(f"Execution Error: {str(e)}")
        return jsonify({
            'status': f'error: {str(e)}',
            'gpt_response': 'Не удалось обработать запрос'
        }), 500

if __name__ == '__main__':
    chromedriver_autoinstaller.install()
    app.run(host='0.0.0.0', port=5000, debug=True)

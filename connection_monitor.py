import time
import datetime
import subprocess
import csv
import platform
import os
import socket
import argparse
import requests
from urllib.request import urlopen
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter

class ConnectionMonitor:
    def __init__(self, host="8.8.8.8", interval=1.0, log_file="connection_log.csv",
                 ping_count=3, timeout=1.0, report_file="connection_report.txt",
                 check_method="all"):
        """
        Инициализация монитора соединения

        :param host: Хост для проверки соединения
        :param interval: Интервал между проверками в секундах
        :param log_file: Файл для сохранения лога соединения
        :param ping_count: Количество ping-запросов за одну проверку
        :param timeout: Таймаут для ping-запроса в секундах
        :param report_file: Файл для сохранения отчета
        :param check_method: Метод проверки соединения: 'ping', 'socket', 'http', 'all'
        """
        self.host = host
        self.interval = interval
        self.log_file = log_file
        self.ping_count = ping_count
        self.timeout = timeout
        self.report_file = report_file
        self.system = platform.system().lower()
        self.check_method = check_method

    def check_connection_ping(self):
        """
        Проверка соединения с помощью ping

        :return: Кортеж (статус соединения (True/False), время отклика в мс или None)
        """
        try:
            # Настройка команды ping в зависимости от операционной системы
            if self.system == "windows":
                cmd = ["ping", "-n", str(self.ping_count), "-w", str(int(self.timeout * 1000)), self.host]
            else:  # Linux, macOS
                cmd = ["ping", "-c", str(self.ping_count), "-W", str(int(self.timeout)), self.host]

            # Выполнение команды ping
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="cp866", timeout=self.timeout * self.ping_count * 1.5)

            # Проверка успешности выполнения
            if result.returncode == 0:
                # Извлечение времени отклика
                output = result.stdout
                if "time=" in output or "время=" in output:
                    lines = output.split('\n')
                    times = []
                    for line in lines:
                        if "time=" in line:
                            parts = line.split("time=")
                            if len(parts) > 1:
                                time_part = parts[1].split()[0].replace("ms", "").strip()
                                try:
                                    times.append(float(time_part))
                                except ValueError:
                                    pass
                        elif "время=" in line:
                            parts = line.split("время=")
                            if len(parts) > 1:
                                time_part = parts[1].split()[0].replace("мс", "").strip()
                                try:
                                    times.append(float(time_part))
                                except ValueError:
                                    pass

                    if times:
                        return True, sum(times) / len(times)
                return True, None
            return False, None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception) as e:
            print(f"Ошибка при выполнении ping: {e}")
            return False, None

    def check_connection_socket(self):
        """
        Проверка соединения с помощью сокета

        :return: Кортеж (статус соединения (True/False), время отклика в мс или None)
        """
        try:
            start_time = time.time()
            # Попытка установить TCP-соединение с хостом
            # Используем порт 53 (DNS) или 80 (HTTP)
            port = 53
            if "." in self.host and not self.host[0].isdigit():  # Если это доменное имя
                try:
                    ip = socket.gethostbyname(self.host)
                except socket.gaierror:
                    return False, None
            else:
                ip = self.host

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                end_time = time.time()
                return True, (end_time - start_time) * 1000  # Время в мс
            return False, None
        except Exception as e:
            print(f"Ошибка при проверке через сокет: {e}")
            return False, None

    def check_connection_http(self):
        """
        Проверка соединения с помощью HTTP-запроса

        :return: Кортеж (статус соединения (True/False), время отклика в мс или None)
        """
        try:
            # Попытка выполнить HTTP-запрос к публичному сайту
            url = "http://www.google.com"
            start_time = time.time()
            response = requests.get(url, timeout=self.timeout)
            end_time = time.time()

            if response.status_code == 200:
                return True, (end_time - start_time) * 1000  # Время в мс
            return False, None
        except requests.exceptions.RequestException:
            try:
                # Альтернативный метод проверки
                start_time = time.time()
                urlopen("http://www.google.com", timeout=self.timeout)
                end_time = time.time()
                return True, (end_time - start_time) * 1000  # Время в мс
            except Exception as e:
                print(f"Ошибка при HTTP-запросе: {e}")
                return False, None

    def check_connection(self):
        """
        Проверяет соединение и записывает результат в лог

        :return: Кортеж (статус соединения (True/False), время проверки, время отклика)
        """
        now = datetime.datetime.now()

        # Проверка соединения разными методами
        if self.check_method == "ping":
            is_connected, ping_time = self.check_connection_ping()
        elif self.check_method == "socket":
            is_connected, ping_time = self.check_connection_socket()
        elif self.check_method == "http":
            is_connected, ping_time = self.check_connection_http()
        else:  # "all" или любой другой вариант
            ping_result = self.check_connection_ping()
            socket_result = self.check_connection_socket()
            http_result = self.check_connection_http()

            # Считаем соединение активным, если хотя бы один метод дал положительный результат
            is_connected = ping_result[0] or socket_result[0] or http_result[0]

            # Берем время отклика от первого успешного метода
            ping_time = None
            for result in [ping_result, socket_result, http_result]:
                if result[0] and result[1] is not None:
                    ping_time = result[1]
                    break

        # Запись в CSV-файл
        file_exists = os.path.isfile(self.log_file)
        with open(self.log_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists:
                writer.writerow(['timestamp', 'datetime', 'connected', 'ping_time'])
            writer.writerow([now.timestamp(), now.strftime('%Y-%m-%d %H:%M:%S'), int(is_connected), ping_time])

        return is_connected, now, ping_time

    def run(self, duration=None):
        """
        Запускает мониторинг соединения на указанное время или бесконечно

        :param duration: Продолжительность мониторинга в секундах (None для бесконечного мониторинга)
        """
        print(f"Запуск мониторинга соединения с {self.host} с интервалом {self.interval} секунд")
        print(f"Метод проверки: {self.check_method}")
        print(f"Данные сохраняются в {self.log_file}")
        print("Нажмите Ctrl+C для остановки...")

        start_time = time.time()
        last_status = None
        disconnect_count = 0
        disconnect_start = None

        try:
            while True:
                is_connected, now, ping_time = self.check_connection()

                # Вывод статуса соединения
                status_str = "СОЕДИНЕНИЕ" if is_connected else "РАЗРЫВ"
                ping_info = f", ping: {ping_time:.1f} ms" if ping_time is not None else ""
                print(f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] {status_str}{ping_info}")

                # Отслеживание изменения статуса соединения
                if last_status is not None and last_status != is_connected:
                    if is_connected:
                        # Восстановление соединения
                        disconnect_duration = (now - disconnect_start).total_seconds()
                        print(f"!!! Соединение восстановлено после {disconnect_duration:.1f} секунд разрыва !!!")
                    else:
                        # Начало разрыва
                        disconnect_count += 1
                        disconnect_start = now
                        print(f"!!! Обнаружен разрыв соединения #{disconnect_count} !!!")

                last_status = is_connected

                # Проверка, не истекло ли время мониторинга
                if duration and time.time() - start_time >= duration:
                    break

                # Ожидание до следующей проверки
                time.sleep(self.interval)

        except KeyboardInterrupt:
            print("\nМониторинг остановлен пользователем")

        finally:
            # Генерация отчета
            self.generate_report()

    # Fix for the generate_report method
    def generate_report(self):
        """
        Генерирует отчет на основе собранных данных
        """
        if not os.path.isfile(self.log_file):
            print("Нет данных для генерации отчета")
            return

        # Чтение данных из лог-файла
        timestamps = []
        datetimes = []
        statuses = []
        ping_times = []

        with open(self.log_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                timestamps.append(float(row['timestamp']))
                datetimes.append(datetime.datetime.strptime(row['datetime'], '%Y-%m-%d %H:%M:%S'))
                statuses.append(bool(int(row['connected'])))

                # Improved handling for ping_time values
                if row['ping_time'] == 'None' or row['ping_time'] == '' or not row['ping_time']:
                    ping_times.append(None)
                else:
                    try:
                        ping_times.append(float(row['ping_time']))
                    except ValueError:
                        print(f"Warning: Could not convert ping_time value '{row['ping_time']}' to float. Using None instead.")
                        ping_times.append(None)

        if not timestamps:
            print("Нет данных для анализа")
            return

        # The rest of the generate_report method remains the same
        # ...

        # Анализ разрывов
        disconnects = []
        disconnect_start = None

        for i, status in enumerate(statuses):
            if i > 0:
                if not status and statuses[i-1]:  # Начало разрыва
                    disconnect_start = datetimes[i]
                elif status and not statuses[i-1] and disconnect_start:  # Конец разрыва
                    disconnects.append((disconnect_start, datetimes[i]))
                    disconnect_start = None

        # Если мониторинг завершился во время разрыва
        if disconnect_start:
            disconnects.append((disconnect_start, datetimes[-1]))

        # Подсчет статистики
        total_checks = len(statuses)
        connected_checks = sum(statuses)
        disconnected_checks = total_checks - connected_checks
        connected_percentage = (connected_checks / total_checks * 100) if total_checks > 0 else 0

        total_time = timestamps[-1] - timestamps[0] if timestamps else 0

        disconnect_durations = []
        for start, end in disconnects:
            duration = (end - start).total_seconds()
            disconnect_durations.append(duration)

        total_disconnect_time = sum(disconnect_durations)
        uptime_percentage = (1 - total_disconnect_time / total_time) * 100 if total_time > 0 else 0

        # Статистика ping
        valid_pings = [p for p in ping_times if p is not None]
        avg_ping = sum(valid_pings) / len(valid_pings) if valid_pings else 0
        max_ping = max(valid_pings) if valid_pings else 0
        min_ping = min(valid_pings) if valid_pings else 0

        # Запись отчета в файл
        with open(self.report_file, 'w',decoding='utf-8') as report:
            report.write("=== ОТЧЕТ О СТАБИЛЬНОСТИ СОЕДИНЕНИЯ ===\n\n")
            report.write(f"Период мониторинга: {datetimes[0]} - {datetimes[-1]}\n")
            report.write(f"Общая продолжительность: {total_time:.1f} секунд ({total_time/3600:.1f} часов)\n\n")

            report.write("--- СТАТИСТИКА СОЕДИНЕНИЯ ---\n")
            report.write(f"Всего проверок: {total_checks}\n")
            report.write(f"Успешных проверок: {connected_checks} ({connected_percentage:.1f}%)\n")
            report.write(f"Неудачных проверок: {disconnected_checks} ({100-connected_percentage:.1f}%)\n")
            report.write(f"Uptime: {uptime_percentage:.2f}%\n")
            report.write(f"Количество разрывов: {len(disconnects)}\n\n")

            if disconnects:
                report.write("--- ДАННЫЕ О РАЗРЫВАХ ---\n")
                for i, (start, end) in enumerate(disconnects):
                    duration = (end - start).total_seconds()
                    report.write(f"Разрыв #{i+1}: начало {start}, конец {end}, продолжительность {duration:.1f} сек\n")

                if disconnect_durations:
                    report.write(f"\nСредняя продолжительность разрыва: {sum(disconnect_durations)/len(disconnect_durations):.1f} сек\n")
                    report.write(f"Максимальная продолжительность разрыва: {max(disconnect_durations):.1f} сек\n")
                    report.write(f"Минимальная продолжительность разрыва: {min(disconnect_durations):.1f} сек\n\n")

            report.write("--- СТАТИСТИКА PING ---\n")
            report.write(f"Средний ping: {avg_ping:.1f} мс\n")
            report.write(f"Максимальный ping: {max_ping:.1f} мс\n")
            report.write(f"Минимальный ping: {min_ping:.1f} мс\n")

        print(f"\nОтчет сохранен в {self.report_file}")

        # Генерация графиков
        self.generate_plots()

    def generate_plots(self):
        """
        Генерирует графики на основе собранных данных
        """
        if not os.path.isfile(self.log_file):
            return

        # Чтение данных из лог-файла
        datetimes = []
        statuses = []
        ping_times = []

        with open(self.log_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                datetimes.append(datetime.datetime.strptime(row['datetime'], '%Y-%m-%d %H:%M:%S'))
                statuses.append(bool(int(row['connected'])))
                ping_val = None if not row['ping_time'] or row['ping_time'] == 'None' else float(row['ping_time'])
                ping_times.append(ping_val)

        # Создание графика статуса соединения
        plt.figure(figsize=(12, 10))

        # График 1: Статус соединения
        plt.subplot(2, 1, 1)
        plt.plot(datetimes, [int(s) for s in statuses], 'b-', label='Статус соединения')
        plt.fill_between(datetimes, [int(s) for s in statuses], color='skyblue', alpha=0.4)
        plt.yticks([0, 1], ['Разрыв', 'Соединение'])
        plt.ylim(-0.1, 1.1)
        plt.title('Статус соединения во времени')
        plt.xlabel('Время')
        plt.ylabel('Статус')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.gca().xaxis.set_major_formatter(DateFormatter('%H:%M:%S'))

        # График 2: Время отклика (ping)
        plt.subplot(2, 1, 2)
        valid_times = [(dt, pt) for dt, pt in zip(datetimes, ping_times) if pt is not None]
        if valid_times:
            valid_datetimes, valid_pings = zip(*valid_times)
            plt.plot(valid_datetimes, valid_pings, 'g-', label='Время отклика')
            plt.fill_between(valid_datetimes, valid_pings, color='lightgreen', alpha=0.4)
            plt.title('Время отклика во времени')
            plt.xlabel('Время')
            plt.ylabel('Время отклика (мс)')
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.gca().xaxis.set_major_formatter(DateFormatter('%H:%M:%S'))
        else:
            plt.text(0.5, 0.5, 'Нет данных о времени отклика',
                    horizontalalignment='center', verticalalignment='center',
                    transform=plt.gca().transAxes)

        plt.tight_layout()
        plt.savefig('connection_stats.png')
        print("График сохранен в connection_stats.png")


if __name__ == "__main__":
    # Настройка аргументов командной строки
    parser = argparse.ArgumentParser(description='Монитор стабильности соединения')
    parser.add_argument('--host', default='8.8.8.8', help='Хост для проверки соединения (по умолчанию: 8.8.8.8)')
    parser.add_argument('--interval', type=float, default=1.0,
                        help='Интервал между проверками в секундах (по умолчанию: 1.0)')
    parser.add_argument('--log-file', default='connection_log.csv',
                        help='Файл для сохранения лога соединения (по умолчанию: connection_log.csv)')
    parser.add_argument('--ping-count', type=int, default=3,
                        help='Количество ping-запросов за одну проверку (по умолчанию: 3)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Таймаут для ping-запроса в секундах (по умолчанию: 1.0)')
    parser.add_argument('--report-file', default='connection_report.txt',
                        help='Файл для сохранения отчета (по умолчанию: connection_report.txt)')
    parser.add_argument('--duration', type=float, default=None,
                        help='Продолжительность мониторинга в секундах (по умолчанию: бесконечно)')
    parser.add_argument('--check-method', default='all', choices=['ping', 'socket', 'http', 'all'],
                        help='Метод проверки соединения (по умолчанию: all)')

    args = parser.parse_args()

    # Создание и запуск монитора
    monitor = ConnectionMonitor(
        host=args.host,
        interval=args.interval,
        log_file=args.log_file,
        ping_count=args.ping_count,
        timeout=args.timeout,
        report_file=args.report_file,
        check_method=args.check_method
    )
    monitor.run(duration=args.duration)

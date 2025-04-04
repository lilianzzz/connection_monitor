import time
import datetime
import subprocess
import csv
import platform
import os
import socket
import argparse
from urllib.request import urlopen
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
import math
import struct
import random

import requests
# requests = requests.Session()
requests.Session().trust_env = False


class ConnectionMonitor:
    def __init__(self, host="8.8.8.8", interval=1.0, log_file="connection_log.csv",
                 ping_count=3, timeout=1.0, report_file="connection_report.txt",
                 check_method="all", http_url="https://www.google.com", socket_port=53):
        """
        Инициализация монитора соединения

        :param host: Хост для проверки соединения
        :param interval: Интервал между проверками в секундах
        :param log_file: Файл для сохранения лога соединения
        :param ping_count: Количество ping-запросов за одну проверку
        :param timeout: Таймаут для ping-запроса в секундах
        :param report_file: Файл для сохранения отчета
        :param check_method: Метод проверки соединения: 'ping', 'socket', 'http', 'udp', 'all'
        :param http_url: URL для проверки HTTP соединения

        """
        self.host = host
        self.interval = interval
        self.log_file = log_file
        self.ping_count = ping_count
        self.timeout = timeout
        self.report_file = report_file
        self.system = platform.system().lower()
        self.check_method = check_method
        self.http_url = http_url
        self.socket_port = 53

    def check_connection_ping(self):
        """
        Проверка соединения с помощью ping с вычислением джиттера и потерь пакетов

        :return: Кортеж (статус (True/False), среднее время отклика в мс, джиттер в мс, % потерь пакетов)
        """
        try:
            if self.system == "windows":
                cmd = ["ping", "-n", str(self.ping_count), "-w", str(int(self.timeout * 1000)), self.host]
                encoding = "cp866" #
            else:
                cmd = ["ping", "-c", str(self.ping_count), "-W", str(int(self.timeout)), self.host]
                encoding = "utf-8"

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding=encoding, text=True,
                                    timeout=self.timeout * self.ping_count * 1.5)
            output = result.stdout

            times = []
            # Ищем строки с информацией о времени отклика
            for line in output.split('\n'):
                if "time=" in line:
                    try:
                        # Для английского варианта
                        time_part = line.split("time=")[1].split()[0].replace("ms", "").strip()
                        times.append(float(time_part))
                    except ValueError:
                        continue
                elif "время=" in line:
                    try:
                        time_part = line.split("время=")[1].split()[0].replace("мс", "").strip()
                        times.append(float(time_part))
                    except ValueError:
                        continue

            successes = len(times)
            packet_loss = ((self.ping_count - successes) / self.ping_count * 100)
            avg_ping = sum(times) / successes if successes > 0 else None
            jitter = (math.sqrt(sum((t - avg_ping) ** 2 for t in times) / (successes - 1))
                      if successes > 1 else 0) if avg_ping is not None else None

            # Если хотя бы один ping прошёл успешно считаем соединение доступным
            is_connected = successes > 0
            return is_connected, avg_ping, jitter, packet_loss
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception) as e:
            print(f"Ошибка при выполнении ping: {e}")
            return False, None, None, None

    def check_connection_socket(self):
        """
        Проверка соединения с помощью сокета

        :return: Кортеж (статус (True/False), время отклика в мс)
        """
        try:
            start_time = time.time()
            port = self.socket_port
            if "." in self.host and not self.host[0].isdigit():
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
                return True, (end_time - start_time) * 1000
            return False, None
        except Exception as e:
            print(f"Ошибка при проверке через сокет: {e}")
            return False, None

    def check_connection_http(self):
        """
        Проверка соединения с помощью HTTP-запроса

        :return: Кортеж (статус (True/False), время отклика в мс)
        """
        try:
            url = self.http_url
            start_time = time.time()
            response = requests.get(url, timeout=self.timeout)
            end_time = time.time()

            if response.status_code == 200:
                return True, (end_time - start_time) * 1000
            return False, None
        except requests.exceptions.RequestException:
            try:
                start_time = time.time()
                urlopen(self.http_url, timeout=self.timeout)
                end_time = time.time()
                return True, (end_time - start_time) * 1000
            except Exception as e:
                print(f"Ошибка при HTTP-запросе: {e}")
                return False, None

    def check_connection_udp(self):
        """
        Проверка соединения с помощью UDP (отправка минимального DNS-запроса)

        :return: Кортеж (статус (True/False), время отклика в мс)
        """
        domain_name = "example.com"
        try:
            transaction_id = random.randint(0, 65535)
            flags = 0x0100  # стандартный запрос
            questions = 1
            answer_rrs = 0
            authority_rrs = 0
            additional_rrs = 0
            header = struct.pack("!HHHHHH", transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)
            # Запрос для домена example.com
            qname = b''.join((bytes([len(part)]) + part.encode() for part in domain_name.split('.'))) + b'\x00'
            qtype = struct.pack("!H", 1)  # A-запись
            qclass = struct.pack("!H", 1)  # IN-класс
            query_packet = header + qname + qtype + qclass

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            start_time = time.time()
            sock.sendto(query_packet, (self.host, 53)) # 53 порт DNS
            data, addr = sock.recvfrom(512)
            end_time = time.time()
            sock.close()
            return True, (end_time - start_time) * 1000
        except Exception as e:
            print(f"Ошибка при проверке через UDP: {e}")
            return False, None

    def check_connection(self):
        """
        Проверяет соединение с использованием выбранного метода(ов) и записывает результат в лог

        :return: Кортеж (статус, время проверки, ping_time, jitter, packet_loss, udp_time)
        """
        now = datetime.datetime.now()
        ping_time = jitter = packet_loss = udp_time = None
        is_connected = False

        if self.check_method == "ping":
            ping_result = self.check_connection_ping()
            is_connected, ping_time, jitter, packet_loss = ping_result
        elif self.check_method == "socket":
            is_connected, ping_time = self.check_connection_socket()
        elif self.check_method == "http":
            is_connected, ping_time = self.check_connection_http()
        elif self.check_method == "udp":
            is_connected, udp_time = self.check_connection_udp()
        elif self.check_method == "all":
            ping_result = self.check_connection_ping()
            socket_result = self.check_connection_socket()
            http_result = self.check_connection_http()
            udp_result = self.check_connection_udp()

            is_connected = (ping_result[0] or socket_result[0] or http_result[0] or udp_result[0])
            ping_time, jitter, packet_loss = ping_result[1], ping_result[2], ping_result[3]
            udp_time = udp_result[1]
            socket_time = socket_result[1]
            http_time = http_result[1]
        else:
            print("Неизвестный метод проверки. Используется 'all'.")
            return self.check_connection()

        # Запись в CSV-файл с новыми метриками
        file_exists = os.path.isfile(self.log_file)
        header = ['timestamp', 'datetime', 'connected', 'ping_time', 'jitter', 'packet_loss', 'udp_time', 'socket_time', 'http_time']
        with open(self.log_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists:
                writer.writerow(header)
            writer.writerow([now.timestamp(), now.strftime('%Y-%m-%d %H:%M:%S'), int(is_connected),
                             ping_time, jitter, packet_loss, udp_time, socket_time, http_time])

        return is_connected, now, ping_time, jitter, packet_loss, udp_time, socket_time, http_time

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
                is_connected, now, ping_time, jitter, packet_loss, udp_time, socket_time, http_time = self.check_connection()

                status_str = "СОЕДИНЕНИЕ" if is_connected else "РАЗРЫВ"
                ping_info = f", ping: {ping_time:.1f} ms" if ping_time is not None else ""
                udp_info = f", udp: {udp_time:.1f} ms" if udp_time is not None else ""
                socket_info = f", socket: {socket_time:.1f} ms" if socket_time is not None else ""
                http_info = f", http: {http_time:.1f} ms" if http_time is not None else ""
                print(f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] {status_str}{ping_info}{udp_info}{socket_info}{http_info}")

                if last_status is not None and last_status != is_connected:
                    if is_connected:
                        disconnect_duration = (now - disconnect_start).total_seconds()
                        print(f"!!! Соединение восстановлено после {disconnect_duration:.1f} секунд разрыва !!!")
                    else:
                        disconnect_count += 1
                        disconnect_start = now
                        print(f"!!! Обнаружен разрыв соединения #{disconnect_count} !!!")

                last_status = is_connected

                if duration and time.time() - start_time >= duration:
                    break

                time.sleep(self.interval)

        except KeyboardInterrupt:
            print("\nМониторинг остановлен пользователем")
        finally:
            self.generate_report()

    def generate_report(self):
        """
        Генерирует отчет на основе собранных данных
        """
        if not os.path.isfile(self.log_file):
            print("Нет данных для генерации отчета")
            return

        timestamps, datetimes, statuses = [], [], []
        ping_times, jitters, packet_losses, udp_times, socket_times, http_times = [], [], [], [], [], []

        with open(self.log_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                timestamps.append(float(row['timestamp']))
                datetimes.append(datetime.datetime.strptime(row['datetime'], '%Y-%m-%d %H:%M:%S'))
                statuses.append(bool(int(row['connected'])))
                ping_times.append(float(row['ping_time']) if row['ping_time'] not in ['None', '', None] else None)
                jitters.append(float(row['jitter']) if row['jitter'] not in ['None', '', None] else None)
                packet_losses.append(float(row['packet_loss']) if row['packet_loss'] not in ['None', '', None] else None)
                udp_times.append(float(row['udp_time']) if row['udp_time'] not in ['None', '', None] else None)
                socket_times.append(float(row['socket_time']) if row['socket_time'] not in ['None', '', None] else None)
                http_times.append(float(row['http_time']) if row['http_time'] not in ['None', '', None] else None)
        if not timestamps:
            print("Нет данных для анализа")
            return

        disconnects = []
        disconnect_start = None
        for i, status in enumerate(statuses):
            if i > 0:
                if not status and statuses[i-1]:
                    disconnect_start = datetimes[i]
                elif status and not statuses[i-1] and disconnect_start:
                    disconnects.append((disconnect_start, datetimes[i]))
                    disconnect_start = None
        if disconnect_start:
            disconnects.append((disconnect_start, datetimes[-1]))

        total_checks = len(statuses)
        connected_checks = sum(statuses)
        disconnected_checks = total_checks - connected_checks
        connected_percentage = (connected_checks / total_checks * 100) if total_checks > 0 else 0
        total_time = timestamps[-1] - timestamps[0] if timestamps else 0

        disconnect_durations = [ (end - start).total_seconds() for start, end in disconnects ]
        total_disconnect_time = sum(disconnect_durations)
        uptime_percentage = (1 - total_disconnect_time / total_time) * 100 if total_time > 0 else 0

        valid_pings = [p for p in ping_times if p is not None]
        avg_ping = sum(valid_pings) / len(valid_pings) if valid_pings else 0
        max_ping = max(valid_pings) if valid_pings else 0
        min_ping = min(valid_pings) if valid_pings else 0

        valid_jitters = [j for j in jitters if j is not None]
        avg_jitter = sum(valid_jitters) / len(valid_jitters) if valid_jitters else 0

        valid_losses = [l for l in packet_losses if l is not None]
        avg_packet_loss = sum(valid_losses) / len(valid_losses) if valid_losses else 0

        valid_udp = [u for u in udp_times if u is not None]
        avg_udp = sum(valid_udp) / len(valid_udp) if valid_udp else 0

        valid_socket = [s for s in socket_times if s is not None]
        avg_socket = sum(valid_socket) / len(valid_socket) if valid_socket else 0

        valid_http = [h for h in http_times if h is not None]
        avg_http = sum(valid_http) / len(valid_http) if valid_http else 0

        with open(self.report_file, 'w', encoding='utf-8') as report:
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
            report.write(f"Средний джиттер: {avg_jitter:.1f} мс (Задержка между моментом передачи и приема сигнала)\n")
            report.write(f"Средняя потеря пакетов: {avg_packet_loss:.1f}%\n\n")

            report.write("--- СТАТИСТИКА UDP ---\n")
            report.write(f"Среднее время отклика UDP: {avg_udp:.1f} мс \n\n")

            report.write("--- СТАТИСТИКА HTTP ---\n")
            report.write(f"Среднее время отклика HTTP: {avg_http:.1f} мс \n\n")

            report.write("--- СТАТИСТИКА СОКЕТОВ ---\n")
            report.write(f"Среднее время отклика сокета: {avg_socket:.1f} мс \n\n")

            report.write("\n=== КОНЕЦ ОТЧЕТА ===")

        print(f"\nОтчет сохранен в {self.report_file}")
        self.generate_plots()

    def generate_plots(self):
        """
        Генерирует графики на основе собранных данных
        """
        if not os.path.isfile(self.log_file):
            return

        datetimes, statuses = [], []
        ping_times, udp_times = [], []

        with open(self.log_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                dt = datetime.datetime.strptime(row['datetime'], '%Y-%m-%d %H:%M:%S')
                datetimes.append(dt)
                statuses.append(bool(int(row['connected'])))
                ping_times.append(float(row['ping_time']) if row['ping_time'] not in ['None', '', None] else None)
                udp_times.append(float(row['udp_time']) if row['udp_time'] not in ['None', '', None] else None)

        plt.figure(figsize=(12, 12))
        # График 1: Статус соединения
        plt.subplot(3, 1, 1)
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
        plt.subplot(3, 1, 2)
        valid_ping = [(dt, pt) for dt, pt in zip(datetimes, ping_times) if pt is not None]
        if valid_ping:
            ping_dt, ping_vals = zip(*valid_ping)
            plt.plot(ping_dt, ping_vals, 'g-', label='Ping')
            plt.fill_between(ping_dt, ping_vals, color='lightgreen', alpha=0.4)
        plt.title('Время отклика (ping) во времени')
        plt.xlabel('Время')
        plt.ylabel('Ping (мс)')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.gca().xaxis.set_major_formatter(DateFormatter('%H:%M:%S'))

        # График 3: Время отклика (UDP)
        plt.subplot(3, 1, 3)
        valid_udp = [(dt, ut) for dt, ut in zip(datetimes, udp_times) if ut is not None]
        if valid_udp:
            udp_dt, udp_vals = zip(*valid_udp)
            plt.plot(udp_dt, udp_vals, 'm-', label='UDP')
            plt.fill_between(udp_dt, udp_vals, color='plum', alpha=0.4)
        plt.title('Время отклика (UDP) во времени')
        plt.xlabel('Время')
        plt.ylabel('UDP (мс)')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.gca().xaxis.set_major_formatter(DateFormatter('%H:%M:%S'))

        plt.tight_layout()
        plt.savefig('connection_stats.png')
        print("График сохранен в connection_stats.png")


if __name__ == "__main__":
    # Создаем парсер аргументов
    parser = argparse.ArgumentParser(description="Монитор стабильности соединения")

# The above code is defining command-line arguments for a network connection monitoring script using
# the `argparse` module in Python. Here is a summary of the arguments being defined:
    parser.add_argument('--host', default='8.8.8.8', help='Хост для проверки соединения (по умолчанию: 8.8.8.8)')
    parser.add_argument('--interval', type=float, default=1.0, help='Интервал между проверками в секундах (по умолчанию: 1.0)')
    parser.add_argument('--log-file', default='connection_log.csv', help='Файл для сохранения лога соединения (по умолчанию: connection_log.csv)')
    parser.add_argument('--ping-count', type=int, default=3, help='Количество ping-запросов за одну проверку (по умолчанию: 3)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Таймаут для ping-запроса в секундах (по умолчанию: 1.0)')
    parser.add_argument('--report-file', default='connection_report.txt', help='Файл для сохранения отчета (по умолчанию: connection_report.txt)')
    parser.add_argument('--duration', type=float, default=None, help='Продолжительность мониторинга в секундах (по умолчанию: бесконечно)')
    parser.add_argument('--check-method', default='all', choices=['ping', 'socket', 'http', 'udp', 'all'], help='Метод проверки соединения (по умолчанию: all)')
    parser.add_argument('--only-report', action="store_true", help='Генерация репорта на основе существующих данных без запуска основного цикла')
    parser.add_argument('--http-url', default='https://www.google.com/', help='URL для проверки соединения (по умолчанию: https://www.google.com/)')
    parser.add_argument('--socket-port', type=int, default=53, help='сокет-порт для проверки соединения (по умолчанию: 53)')

    args, unknown = parser.parse_known_args()

    # Выводим текущие настройки
    print("\n🔹 ТЕКУЩИЕ НАСТРОЙКИ:")
    for arg, value in vars(args).items():
        print(f"  {arg}: {value}")

    # Спрашиваем пользователя, хочет ли он изменить что-то
    print("\n🔹 Введите новые значения (или нажмите Enter, чтобы оставить по умолчанию)")

    # Для флага --generate-report обрабатываем ввод "y/n"
    only_report_input = input(f" Для генерации отчета введите - 0, \n Для запуска основной программы введите - 1 \n (по умолчанию запустится основная программа: {'1' if args.only_report else '0'})\n: ").strip().lower()
    if only_report_input in ["1"]:
        args.only_report = True
    elif only_report_input in ["0"]:
        args.only_report = False

    # Запуск основного цикла
    if args.only_report == True:
        ConnectionMonitor().generate_report()
    elif args.only_report == False:
        args.host = input(f"  Хост [{args.host}]: ") or args.host
        args.interval = float(input(f"  Интервал опроса (сек) [{args.interval}]: ") or args.interval)
        args.ping_count = int(input(f"  Количество пингов за одну проверку [{args.ping_count}]: ") or args.ping_count)
        args.timeout = float(input(f"  Таймаут пинга (сек) [{args.timeout}]: ") or args.timeout)
        args.log_file = input(f"  Файл лога [{args.log_file}]: ") or args.log_file
        args.report_file = input(f"  Файл отчета [{args.report_file}]: ") or args.report_file
        args.duration = input(f"  Продолжительность мониторинга (сек) [{args.duration}]: ") or args.duration
        args.http_url = input(f"  URL для проверки HTTP соединения [{args.http_url}]: ") or args.http_url
        args.socket_port = input(f"  Сокет-Порт для проверки UDP-соединения [{args.socket_port}]: ") or args.socket_port

        # Вывод финальных аргументов
        print("\n✅ Запуск с параметрами:")
        for arg, value in vars(args).items():
            print(f"  {arg}: {value}")

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

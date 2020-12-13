"""
HTTP Server for managing the Ballu air conditioner over a local network

v1.0.1
- удалены закоментированные строки вызывающие логирование
- функции (pad, unpad), которые вызывались в encrypt_and_sign и decrypt_and_validate удалены, а функционал перемещен непосредственно в них
- удалена функция hmac_digest, а обработка перемещена непосредственно в места вызова
- в class Dimmer исправлены неправильно установленные значения ON OFF

v1.0.2
- добавлена документация ко всем блокам

v1.03
- добавлена документация к строкам
- добавлен вывод в консоль почти из всхе блоков для отслеживания алгоритма взаимодействия с АС
- код получения локального IP выведен из KEEP_ALIVE в функцию get_local_ip 
"""


__author__ = 'AlexFdlv@bk.ru (Alex Fdlv)'

import argparse
import base64
from dataclasses import dataclass, field, fields
from dataclasses_json import dataclass_json
import enum
import hmac
from http.client import HTTPConnection, InvalidURL
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
import json
import math
import paho.mqtt.client as mqtt
import queue
import random
from retry import retry
import socket
import string
import sys
import threading
import time
import typing
from urllib.parse import parse_qs, urlparse, ParseResult

from Crypto.Cipher import AES


@dataclass_json
@dataclass
class LanConfig:
  '''Класс - Набор ключей полученных из файла json'''
  lanip_key: str
  lanip_key_id: int
  random_1: str
  time_1: int
  random_2: str
  time_2: int

@dataclass
class Encryption:
  '''Класс - Набор ключей шифрования созданных на основе lanip_key'''
  sign_key: bytes
  crypto_key: bytes
  iv_seed: bytes
  cipher: AES
  
  def __init__(self, lanip_key: bytes, msg: bytes):
    self.sign_key = self._build_key(lanip_key, msg + b'0')
    self.crypto_key = self._build_key(lanip_key, msg + b'1')
    self.iv_seed = self._build_key(lanip_key, msg + b'2')[:AES.block_size]
    self.cipher = AES.new(self.crypto_key, AES.MODE_CBC, self.iv_seed)

  @classmethod
  def _build_key(cls, lanip_key: bytes, msg: bytes) -> bytes:
    '''Метод - создание ключа'''
    return hmac.digest(lanip_key, hmac.digest(lanip_key, msg, 'sha256') + msg, 'sha256')

@dataclass
class Config:
  '''Класс - Набор всех ключей: полученных из файла и шифрования/дешифрования'''
  lan_config: LanConfig
  app: Encryption
  dev: Encryption
  
  def __init__(self):
    with open(_parsed_args.config, 'rb') as f:
      self.lan_config = LanConfig.from_json(f.read().decode('utf-8'))
    self._update_encryption()
    
  def update(self):
    """Обновляет сохраненную в файле .json конфигурацию локальной сети и данные шифрования."""
    with open(_parsed_args.config, 'wb') as f:
      f.write(self.lan_config.to_json().encode('utf-8'))
    self._update_encryption()

  def _update_encryption(self):
    '''Обновляет данные шифрования'''
    lanip_key = self.lan_config.lanip_key.encode('utf-8')
    random_1 = self.lan_config.random_1.encode('utf-8')
    random_2 = self.lan_config.random_2.encode('utf-8')
    time_1 = str(self.lan_config.time_1).encode('utf-8')
    time_2 = str(self.lan_config.time_2).encode('utf-8')
    self.app = Encryption(lanip_key, random_1 + random_2 + time_1 + time_2)
    self.dev = Encryption(lanip_key, random_2 + random_1 + time_2 + time_1)

class Error(Exception):
  """Класс - ошибки обработчиков"""
  pass


class FanSpeed(enum.IntEnum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  AUTO = 0
  LOWER = 5
  LOW = 6
  MEDIUM = 7
  HIGH = 8
  HIGHER = 9
class SleepMode(enum.IntEnum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  STOP = 0
  ONE = 1
  TWO = 2
  THREE = 3
  FOUR = 4
class AcWorkMode(enum.IntEnum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  FAN = 0
  HEAT = 1
  COOL = 2
  DRY = 3
  AUTO = 4
class AirFlow(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  OFF = 0
  ON = 1
class Dimmer(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  OFF = 0
  ON = 1  
class DoubleFrequency(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  OFF = 0
  ON = 1
class Economy(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  OFF = 0
  ON = 1
class EightHeat(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  OFF = 0
  ON = 1
class FastColdHeat(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  OFF = 0
  ON = 1
class Power(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  OFF = 0
  ON = 1
class Quiet(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  OFF = 0
  ON = 1
class TemperatureUnit(enum.Enum):
  '''Названия статуса свойства на основе полученного числового значения свойства'''
  CELSIUS = 0
  FAHRENHEIT = 1


class Properties(object):
  '''Класс - получение свойств и их параметров'''
  @classmethod
  def _get_metadata(cls, attr: str):
    '''Метод - получение метаданных'''
    return cls.__dataclass_fields__[attr].metadata

  @classmethod
  def get_type(cls, attr: str):
    '''Метод - получение типа данных свойства'''
    return cls.__dataclass_fields__[attr].type

  @classmethod
  def get_base_type(cls, attr: str):
    '''Метод - получение базового типа данных свойства'''
    return cls._get_metadata(attr)['base_type']

  @classmethod
  def get_read_only(cls, attr: str):
    '''Метод - получение характеристики "только для чтения" свойства'''
    return cls._get_metadata(attr)['read_only']

@dataclass_json
@dataclass
class AcProperties(Properties):
  '''Класс - Набор свойств АС'''
  f_electricity: int = field(default=100, metadata={'base_type': 'integer', 'read_only': True})
  f_e_arkgrille: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_incoiltemp: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_incom: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_indisplay: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_ineeprom: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_inele: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_infanmotor: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_inhumidity: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_inkeys: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_inlow: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_intemp: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_invzero: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_outcoiltemp: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_outeeprom: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_outgastemp: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_outmachine2: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_outmachine: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_outtemp: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_outtemplow: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_e_push: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_filterclean: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_humidity: int = field(default=50, metadata={'base_type': 'integer', 'read_only': True})  # Humidity
  f_power_display: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': True})
  f_temp_in: float = field(default=81.0, metadata={'base_type': 'decimal', 'read_only': True})  # EnvironmentTemperature (Fahrenheit)
  f_voltage: int = field(default=0, metadata={'base_type': 'integer', 'read_only': True})
  t_backlight: Dimmer = field(default=Dimmer.OFF, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: Dimmer[x]}})  # DimmerStatus
  t_device_info: bool = field(default=0, metadata={'base_type': 'boolean', 'read_only': False})
  t_display_power: bool = field(default=None, metadata={'base_type': 'boolean', 'read_only': False})
  t_eco: Economy = field(default=Economy.OFF, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: Economy[x]}})
  t_fan_leftright: AirFlow = field(default=AirFlow.OFF, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: AirFlow[x]}})  # HorizontalAirFlow
  t_fan_mute: Quiet = field(default=Quiet.OFF, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: Quiet[x]}})  # QuiteModeStatus
  t_fan_power: AirFlow = field(default=AirFlow.OFF, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: AirFlow[x]}})  # VerticalAirFlow
  t_fan_speed: FanSpeed = field(default=FanSpeed.AUTO, metadata={'base_type': 'integer', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: FanSpeed[x]}})  # FanSpeed
  t_ftkt_start: int = field(default=None, metadata={'base_type': 'integer', 'read_only': False})
  t_power: Power = field(default=Power.ON, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: Power[x]}})  # PowerStatus
  t_run_mode: DoubleFrequency = field(default=DoubleFrequency.OFF, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: DoubleFrequency[x]}})  # DoubleFrequency
  t_setmulti_value: int = field(default=None, metadata={'base_type': 'integer', 'read_only': False})
  t_sleep: SleepMode = field(default=SleepMode.STOP, metadata={'base_type': 'integer', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: SleepMode[x]}})  # SleepMode
  t_temp: int = field(default=81, metadata={'base_type': 'integer', 'read_only': False})  # CurrentTemperature
  t_temptype: TemperatureUnit = field(default=TemperatureUnit.FAHRENHEIT, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: TemperatureUnit[x]}})  # CurrentTemperatureUnit
  t_temp_eight: EightHeat = field(default=EightHeat.OFF, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: EightHeat[x]}})  # EightHeatStatus
  t_temp_heatcold: FastColdHeat = field(default=FastColdHeat.OFF, metadata={'base_type': 'boolean', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: FastColdHeat[x]}})  # FastCoolHeatStatus
  t_work_mode: AcWorkMode = field(default=AcWorkMode.AUTO, metadata={'base_type': 'integer', 'read_only': False,
    'dataclasses_json': {'encoder': lambda x: x.name, 'decoder': lambda x: AcWorkMode[x]}})  # WorkModeStatus

@dataclass
class Data:
  """Класс - Текущее хранилище данных: команды, обновления и свойства.
     
     Содержит: очереди команд, счетчики, блокировки потоков,
     свойства АС
     Методы: получение свойств, обновление свойств при изменении  
  """
  commands_queue = queue.Queue() # объект - очередь команд
  commands_seq_no = 0 # сброс счетчика seq_no
  commands_seq_no_lock = threading.Lock()
  updates_seq_no = 0 # сброс счетчика 
  updates_seq_no_lock = threading.Lock()
  properties: Properties # объект класса Properties
  properties_lock = threading.Lock() # объект - блокиратор потока, для доступа к хранилищу свойств АС

  def get_property(self, name: str):
    """Метод - получение свойств из хранилища"""
    with self.properties_lock: # заблокировать поток для получения значения свойства АС из хранилища
      return getattr(self.properties, name) # получение свойства из хранилища properties и возврат

  def update_property(self, name: str, value) -> None:
    """Метод - обновление свойств в хранилище, если изменены"""
    with self.properties_lock: # заблокировать поток для обновления значения свойства АС из хранилища
      old_value = getattr(self.properties, name) # получение свойства из хранилища properties
      if value != old_value: # если новое значение не равно старому
        setattr(self.properties, name, value) # запись свойства в хранилище properties


class KeepAliveThread(threading.Thread):
  """Поток для периодической отправки запросов на АС для поддержания связи.

     Запросы представляют из себя POST или PUT запросы на АС с информацией
     об этом сервере. Т.е. АС из этих запросов извлекает и сохраняет информацию
     о том, куда в последствии отправлять данные, т.е. на этот сервер.
     Периодичность по-умолчанию 10 секунд.  
  """

  _KEEP_ALIVE_INTERVAL = 10.0 # интервал отправки сапросов, секундр

  def __init__(self):
    self.run_lock = threading.Condition() # создание объекта состояния потока
    self._alive = False # статус потока (живой - True / не живой - False)
    self._headers = { # создание словаря для заговловка запроса
      'Accept': 'application/json',
      'Connection': 'Keep-Alive',
      'Content-Type': 'application/json',
      'Host': _parsed_args.ip,
      'Accept-Encoding': 'gzip'
    }
    self._json = { # создание словаря для тела запроса
      'local_reg': {
        'ip': get_local_ip(),
        'notify': 0,
        'port': _parsed_args.port,
        'uri': "/local_lan"
      }
    }
    super(KeepAliveThread, self).__init__(name='Keep Alive thread')

  @retry(exceptions=ConnectionError, delay=0.5, max_delay=20, backoff=1.5) # декоратор для повторных попыток установки соединения
  def _establish_connection(self, conn: HTTPConnection) -> None:
    '''Метод - установка соединения (отправка запросов)'''
    method = 'PUT' if self._alive else 'POST' # выбор метода для запросов (PUT, если поток запросов живой, иначе POST)
    try:
      conn.request(method, '/local_reg.json', json.dumps(self._json), self._headers) # отправить запрос (метод, УРЛ, тело, заголовок)
      resp = conn.getresponse() # получить ответ
      print('KA***Отправлены рег данные методом',method,' получен ответ',resp.status)
      if resp.status != HTTPStatus.ACCEPTED: # если статус ответа не равен ACCEPTED
        raise ConnectionError('Recieved invalid response for local_reg: ' + repr(resp)) # 
      resp.read() # прочитать ответ
    except:
      self._alive = False # установить статус потока - не живой (если ответ от АС был не ACCEPTED)
      raise
    finally:
      conn.close() # закрыть соединение
    self._alive = True # установить статус потока - живой

  def run(self) -> None:
    '''Метод - Создание и установка соединения'''
    with self.run_lock: # заблокировать поток
      try:
        conn = HTTPConnection(_parsed_args.ip, timeout=5) # создать соединение
      except InvalidURL: # если было исключение "неверный URL"
        _httpd.shutdown() # выключить http сервер
        return # возврат (выход из метода)
      while True: # цикл без условия завершения (безконечный)
        try:
          self._establish_connection(conn) # выполнить метод - установка соединения
        except: # если были исключения
          _httpd.shutdown() # выключить http сервер
          return # возврат (выход из метода)
        self._json['local_reg']['notify'] = int(_data.commands_queue.qsize() > 0 or self.run_lock.wait(self._KEEP_ALIVE_INTERVAL)) #!!!ToDo записать число (разобраться как вычисляется) в тело запроса, в параметр notify (уведомлене) (разобраться зачем)

class QueryStatusThread(threading.Thread):
  """Поток для постановки в очередь команд на запрос значений всех свойств АС.
     
     Работает автономно. Ни откуда не вызывается. Каждые 600сек ставит в очередь 
     запрос всех свойств. 
     Очередь команд будет обработана только после запуска потока KeepAlive
     и сервера HTTP для обмена данными с АС.
  """
  
  _STATUS_UPDATE_INTERVAL = 600.0 # интервал обновления состояния, секунд
  _WAIT_FOR_EMPTY_QUEUE = 10.0 # ожидание пустой очереди, секунд

  def __init__(self):
    self._next_command_id = 0 # id команды
    super(QueryStatusThread, self).__init__(name='Query Status thread')

  def run(self) -> None:
    '''Метод - для всех свойств АС формирование данных для запроса и постановка в очередь'''
    while True: # цикл без условия завершения (безконечный)
      # In case the AC is stuck, and not fetching commands, avoid flooding
      # the queue with status updates.
      # В случае, если AC застрял и не получает команды, избегайте наводнения очереди обновлениями состояния
      while _data.commands_queue.qsize() > 10: # пока очередь больше 10
        time.sleep(self._WAIT_FOR_EMPTY_QUEUE) # приостановить выполнение на _WAIT_FOR_EMPTY_QUEUE секунд
      for data_field in fields(_data.properties): # для всех свойств АС из хранилища свойств
        command = { # формирование команды для запроса свойства у АС
          'cmds': [{
            'cmd': {
              'method': 'GET', # метод запроса
              'resource': 'property.json?name=' + data_field.name, # запрос определенного свойства АС
              'uri': '/local_lan/property/datapoint.json', # адрес для ответа
              'data': '',
              'cmd_id': self._next_command_id, # id команды
            }
          }]
        }
        self._next_command_id += 1 # увеличить id команды на 1
        _data.commands_queue.put_nowait((command, None)) # поставить словарь comand, и "ничего" в очередь
        print('QS***команда отправлена в очередь:',command)
      if _keep_alive: # если существует поток _keep_alive
        with _keep_alive.run_lock: # заблокировать поток
          _keep_alive.run_lock.notify() #!!!ToDo что-то уведомить в потоке
      time.sleep(self._STATUS_UPDATE_INTERVAL) # приостановить цикл на _STATUS_UPDATE_INTERVAL секунд

class HTTPRequestHandler(BaseHTTPRequestHandler):
  """Класс - Обработчики запросов на этот http сервер"""

  def do_HEAD(self, code: HTTPStatus = HTTPStatus.OK) -> None:
    """Установка статуса ответа и заголовка ответа 'Content-type' """
    print('HEAD***Статус ответа - ',code)
    self.send_response(code) # отправляет статус в ответ на запрос
    if code == HTTPStatus.OK: # если статус = ОК:
      self.send_header('Content-type', 'application/json') # задать в заголовке тип контента
    self.end_headers() # завершение заголовка

  def do_GET(self) -> None:
    """Метод - Обработка GET запросов."""
    parsed_url = urlparse(self.path) # извлечение url, на который пришел GET запрос
    query = parse_qs(parsed_url.query) # извлечение запроса в словарь из строки запроса
    handler = self._HANDLERS_MAP.get(parsed_url.path) # получение обработчика на основе пути запроса из таблицы _HANDLERS_MAP
    if handler: # если обработчик существует
      print('GET***Получен GET запрос. Выбран обработчик -',handler.__name__,'. Передан запрос query - ',query)
      handler(self, parsed_url.path, query, {}) # запуск обработчика и передача ему: пути, запроса, и пустого словаря с данными
      return # возврат (выход из метода)
    self.do_HEAD(HTTPStatus.NOT_FOUND) # ответить на запрос со статусом 404 (срабатывает, если обрабтчик не найден)

  def do_POST(self):
    """Метод - Обработка POST запросов."""
    content_length = int(self.headers['Content-Length']) # получение длины контента из заголовка
    post_data = self.rfile.read(content_length) # чтение данных длинной content_length
    parsed_url = urlparse(self.path) # извлечение url, на который пришел POST запрос
    query = parse_qs(parsed_url.query) # извлечение запроса в словарь из строки запроса
    data = json.loads(post_data) # парсинг в словарь полученной JSON строки
    handler = self._HANDLERS_MAP.get(parsed_url.path) # получение обработчика на основе пути запроса из таблицы _HANDLERS_MAP
    if handler: # если обработчик существует
      print('POST***Получен POST запрос. Выбран обработчик -',handler.__name__,'. query - ',query,'. data - ',data)
      handler(self, parsed_url.path, query, data) # запуск обработчика и передача ему: пути, запроса, и данных
      return # возврат (выход из метода)
    self.do_HEAD(HTTPStatus.NOT_FOUND) # ответить на запрос со статусом 404 (срабатывает, если обрабтчик не найден)

  def key_exchange_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает обмен ключами.
       
       Срабатывает при POST запросе со стороны АС на адрес
       /local_lan/key_exchange.json

       Принимает rundom и time от АС и передает заново сгенерированные.
       Обратите внимание, что ключевым компонентом шифрования является lanip_key, 
       сопоставленный с lanip_key_id, предоставленным AC. 
       Эта секретная часть предоставляется сервером HiSense. 
       К счастью, lanip_key_id (и lanip_key) являются статическими для данного АС.
    """
    try:
      print('KEY_EXCH***Получены данные - ', data)
      key = data['key_exchange'] # извлечение из полученных данных блока key_exchange
      if key['ver'] != 1 or key['proto'] != 1 or key.get('sec'): # проверка допустимых значений
        raise KeyError() # переход к except KeyError:
      _config.lan_config.random_1 = key['random_1'] # чтение значения random_1 из кей и запись в хранилище lan_config
      _config.lan_config.time_1 = key['time_1'] # чтение значения time_1 и запись в хранилище lan_config
    except KeyError: # обраобтка исключения KeyError
      self.do_HEAD(HTTPStatus.BAD_REQUEST) # отправить в ответ статус BAD_REQUEST
      return # возврат (выход из метода)
    if key['key_id'] != _config.lan_config.lanip_key_id: # если значение key_id не равно значению lanip_key_id в хранилище lan_config
      self.do_HEAD(HTTPStatus.NOT_FOUND) # отправить в ответ статус BAD_REQUEST
      return # возврат (выход из метода)
    _config.lan_config.random_2 = ''.join(random.choices(string.ascii_letters + string.digits, k=16)) # формирование значения random_2 и запись в хранилище lan_config
    _config.lan_config.time_2 = time.monotonic_ns() % 2**40 # формирование значения time_2 и запись в хранилище lan_config
    _config.update() # запись значений в файл .json
    self.do_HEAD(HTTPStatus.OK) # отправить в ответ статус ОК
    print('KEY_EXCH***В WJ отправлены данные - ',{"random_2": _config.lan_config.random_2,"time_2": _config.lan_config.time_2})
    self._write_json({"random_2": _config.lan_config.random_2,"time_2": _config.lan_config.time_2}) # отправить в ответ JSON со значениями random_2 и time_2

  def command_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает запрос команды.

       Срабатывает при GET запросе со стороны АС на адрес
       /local_lan/commands.json

      Запрос поступает от AC. Метод принимает команду из очереди,
      формирует JSON, шифрует,подписывает его, и передает его в АС.
    """
    command = {} # создает пустой словарьь command
    with _data.commands_seq_no_lock: #!!!ToDo что-то связанно с блокировкой потока (разобраться)
      command['seq_no'] = _data.commands_seq_no # добавить в словарь ключ seq_no и присвоить ему значение счетчика _data.commands_seq_no
      _data.commands_seq_no += 1 # увеличить значение счетчика на 1
    try:
      command['data'], property_updater = _data.commands_queue.get_nowait() # добавить в словарь command ключ data и присвоить ему значение взятое из очереди, так же взять из очереди значение для property_updater
    except queue.Empty: # если очередь пустая
      command['data'], property_updater = {}, None # в ключ data поместить пустой словарь, а в property_updater значение None (т.е. переменная property_updater как бы перестает существовать)
    print('COMMAND_HANDLER***Отправлены данные на шифровку',command)
    self.do_HEAD(HTTPStatus.OK) # отправить в ответ статус ОК   
    self._write_json(encrypt_and_sign(command)) # зашифровать и подписать словарь command и отправить в ответ на запрос
    if property_updater: # если property_updater существует
      property_updater() # !!!ToDo разобраться что это за property_updater, нигде нет этой функции

  def property_update_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает запрос на обновление свойств.

       Срабатывает при POST запросе со стороны АС на адрес
       /local_lan/property/datapoint.json

       Расшифровывает, проверяет и помещает значение в локальное хранилище свойств.
    """
    try:
      update = decrypt_and_validate(data) # расшифровать, проверить data и записать в update
      print('PROPERTY_UPDATE_HANDLER***Получены данные с шифровки',update)
    except Error: # если ошибка
      self.do_HEAD(HTTPStatus.BAD_REQUEST) # Ответить на запрос со статусом BAD_REQUEST
      return # возврат (выход из метода)
    self.do_HEAD(HTTPStatus.OK) # Ответить на запрос со статусом ОК
    with _data.updates_seq_no_lock:
      # Every once in a while the sequence number is zeroed out, so accept it.
      # Время от времени порядковый номер обнуляется, так что примите его.
      # if _data.updates_seq_no > update['seq_no'] and update['seq_no'] > 0:
      #   logging.error('Stale update found %d. Last update used is %d.',
      #                 (update['seq_no'], _data.updates_seq_no)) 
      #   return  # Old update
      _data.updates_seq_no = update['seq_no'] #!!!ToDo записать значение seq_no в updates_seq_no (Зачем? разобраться)
    name = update['data']['name'] # получение имени свойства
    data_type = _data.properties.get_type(name) # получение типа данных для имени свойства из хранилища свойств
    value = data_type(update['data']['value']) # привести значение свойства к нужному типу данных
    _data.update_property(name, value) # передать свойство и значение в хранилище
    
  def get_status_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает запрос на получение свойств.

       Срабатывает при GET запросе со стороны браузера или умного дома на адрес
       /status

       Возвращает текущее внутренне сохраненное состояние АС из хранилища данных.
    """
    with _data.properties_lock: # заблокировать обращение к потоку со свойствами
      data = _data.properties.to_dict() # преобразовать набор свойств в словарь
    print('GET_STATUS_HANDLER***В WJ отправлены данные - ',data)
    self.do_HEAD(HTTPStatus.OK) # Ответить на запрос со статусом ОК
    self._write_json(data) # Отправить ответ на запрос

  def queue_command_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает запрос на постановку в очередь команды для АС.

       Срабатывает при GET запросе со стороны браузера или умного дома на адрес
       /command

       Разбирает запрос и отправляет в очередь команд свойства и значения, которое нужно изменить
    """
    try:
      print('QUEUE_COMMAND_HANDLER***В QUEUE_COMMAND отправлены данные - ',query['property'][0], query['value'][0])
      queue_command(query['property'][0], query['value'][0]) # Отправить свойство и значение на формирование команды и постановку в очередь команд
    except: # если исключение
      self.do_HEAD(HTTPStatus.BAD_REQUEST) # Ответить на запрос со статусом BAD_REQUEST
      return # возврат (выход из метода)
    self.do_HEAD(HTTPStatus.OK) # Ответить на запрос со статусом ОК
    self._write_json({'queued commands': _data.commands_queue.qsize()}) # Отправить в ответ на запрос количество команд в очереди

  def _write_json(self, data: dict) -> None:
    """Отправить данные в виде JSON."""
    self.wfile.write(json.dumps(data).encode('utf-8')) # Преобразовать (сериализовать) принятый словарь в строку JSON, кодировать в utf-8 и записать в тело ответа
    print('WRITE_JSON*** - ',data)

  _HANDLERS_MAP = {
    '/status': get_status_handler,
    '/command': queue_command_handler,
    '/local_lan/key_exchange.json': key_exchange_handler,
    '/local_lan/commands.json': command_handler,
    '/local_lan/property/datapoint.json': property_update_handler,
    '/local_lan/property/datapoint/ack.json': property_update_handler,
    '/local_lan/node/property/datapoint.json': property_update_handler,
    '/local_lan/node/property/datapoint/ack.json': property_update_handler,
    # TODO: Handle these if needed.
    # '/local_lan/node/conn_status.json': connection_status_handler,
    # '/local_lan/connect_status': module_request_handler,
    # '/local_lan/status.json': setup_device_details_handler,
    # '/local_lan/wifi_scan.json': module_request_handler,
    # '/local_lan/wifi_scan_results.json': module_request_handler,
    # '/local_lan/wifi_status.json': module_request_handler,
    # '/local_lan/regtoken.json': module_request_handler,
    # '/local_lan/wifi_stop_ap.json': module_request_handler,
  }


def encrypt_and_sign(data: dict) -> dict:
  '''Шифровка и подпись'''
  text = json.dumps(data).encode('utf-8')
  pad_text = text.ljust(math.ceil(len(text) / AES.block_size) * AES.block_size, bytes([0]))
  return {
    "enc": base64.b64encode(_config.app.cipher.encrypt(pad_text)).decode('utf-8'),
    "sign": base64.b64encode(hmac.digest(_config.app.sign_key, text, 'sha256')).decode('utf-8')
  }

def decrypt_and_validate(data: dict) -> dict:
  '''Расшифровка и проверка'''
  text = _config.dev.cipher.decrypt(base64.b64decode(data['enc'])).rstrip(bytes([0]))
  sign = base64.b64encode(hmac.digest(_config.dev.sign_key, text, 'sha256')).decode('utf-8')
  if sign != data['sign']:
    raise Error('Invalid signature for %s!' % text.decode('utf-8'))
  return json.loads(text.decode('utf-8'))

def queue_command(name: str, value, recursive: bool = False) -> None:
  '''Метод - Формирование команды на изменение свойства АС и постановка в очередь
  
     Принимает имя свойства и его значение, формирует данные для отправки на АС
     и ставит в очередь на исполнение.
  '''

  if _data.properties.get_read_only(name): # Если атрибут read-only свойства name = True
    raise Error('Cannot update read-only property "{}".'.format(name)) # Вызвать ошибку "Невозможно изменить свойство только для чтения"
  data_type = _data.properties.get_type(name) # получить тип данных значения свойства
  base_type = _data.properties.get_base_type(name) # получить базовый тип данных значения свойства
  if issubclass(data_type, enum.Enum): # Если data_type класс является наследником класса enum.Enum
    data_value = data_type[value].value # То значение взять из этого наследника и преобразовать значение в тип данных data_type
  elif data_type is int and type(value) is str and '.' in value: # иначе если тип данных свойства int И тип значения str и есть '.' в значении
    # Round rather than fail if the input is a float.
    # This is commonly the case for temperatures converted by HA from Celsius.
    # Округлить, если значение является числом с плавающей точной.
    #  Так обычно бывает при преобразовании температуры из цельсия.
    data_value = round(float(value)) # преобразовать значение в число с плавающей запятой и округлить
  else: # иначе
    data_value = data_type(value) # преобразовать значение в тип данных data_type
  command = { # формирование команды для изменения
    'properties': [{
      'property': {
        'base_type': base_type,
        'name': name,
        'value': data_value,
        'id': ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
      }
    }]
  }
  # В командах (как правило) нет acks, поэтому также ставьте в очередь обновление свойства, 
  # которое будет запущено после отправки команды
  typed_value = data_type[value] if issubclass(data_type, enum.Enum) else data_value # создание значения необходимого типа
  property_updater = lambda: _data.update_property(name, typed_value) # создание функции для обновления свойств в локальном хранилище
  _data.commands_queue.put_nowait((command, property_updater)) # поместить в очередь команду и функцию для обновления свойств
  print('QUEUE_COMMAND***В очередь отправлена команда - ',command,'и property_updater', property_updater)
  # Включение режима FastColdHeat
  if name == 't_temp_heatcold' and typed_value is FastColdHeat.ON:
    # рекурсивно вызвать функцию (саму себя) для изменения четырех свойств
    queue_command('t_fan_speed', 'AUTO', True)
    queue_command('t_fan_mute', 'OFF', True)
    queue_command('t_sleep', 'STOP', True)
    queue_command('t_temp_eight', 'OFF', True)
  if not recursive: # если функция вызвана не рекурсивно
    with _keep_alive.run_lock: # заблокировать поток _keep_alive
      _keep_alive.run_lock.notify() # приостановить выполение keep_alive

def ParseArguments() -> argparse.Namespace:
  """Разбор аргументов командной строки.

     Извлекает аргументы из командной строки.
     Разбирает на составляющие и возвращает 
     пространство имен Namespase с аргументами: 
     Namespace(config='имя файла.json', ip='xxx.xxx.xxx.xxx', port=номер порта)
  """
  arg_parser = argparse.ArgumentParser(
      description='JSON сервер для кондиционера Ballu.',
      allow_abbrev=False)
  arg_parser.add_argument('-p', '--port', required=True, type=int,
                          help='Порт сервера.')
  arg_parser.add_argument('--ip', required=True,
                          help='IP адрес кондиционера.')
  arg_parser.add_argument('--config', required=True,
                          help='Имя файла .json с lanip_key.')
  return arg_parser.parse_args()

def get_local_ip():
  '''Получение локального IP адреса
  
     Возвращает IP адрес сервера, на котором запущен модуль
  '''
  sock = None # пустой сокет
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # создание объекта сокета
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # установка параметров сокета
    sock.connect(('10.255.255.255', 1)) # подключение куда-то
    local_ip = sock.getsockname()[0] # получение локального ip (ip на котором выполняется этот модуль)
  finally:
    if sock: # если сокет существует
      sock.close() # закрыть сокет
  return local_ip


if __name__ == '__main__':
    _parsed_args = ParseArguments() # создание объекта с аргументами запуска  # type: argparse.Namespace
    
    _config = Config() # создание объекта с набором ключей шифрования/дешифрования информации при обмене с АС
    print('MAIN***Создан объект _config:',_config)

     
    _data = Data(properties=AcProperties()) # создание объекта - хранилаща очереди команд, свойств АС с дефолтными значениями
    print('MAIN***Создан объект _data:',_data)
    
    _keep_alive = None # удаление потока keep_alive type: typing.Optional[KeepAliveThread]
    
    print('MAIN***Запуск потока query_status:')
    query_status = QueryStatusThread() # создание потока - очередь запросов свойств АС
    query_status.start() # запуск потока
        
    print('MAIN***Запуск потока keep_alive:')
    _keep_alive = KeepAliveThread() # создание потока поддержки связи с АС
    _keep_alive.start() # запуск потока
    
    print('MAIN***Запуск сервера http:')
    _httpd = HTTPServer(('', _parsed_args.port), HTTPRequestHandler) # создание http сервера, передача номера порта, на котором будет работать сервер и имя класса обработчика событий
    try:
      _httpd.serve_forever() # запуск http сервера в потоке
    except KeyboardInterrupt:
      pass
      _httpd.server_close() # остановка http сервера

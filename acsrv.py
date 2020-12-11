"""
HTTP Server for managing the Ballu air conditioner over a local network

v1.0.1
- удалены закоментированные строки вызывающие логирование
- функции (pad, unpad), которые вызывались в encrypt_and_sign и decrypt_and_validate удалены, а функционал перемещен непосредственно в них
- удалена функция hmac_digest, а обработка перемещена непосредственно в места вызова
- в class Dimmer исправлены неправильно установленные значения ON OFF

v1.0.2
- добавлена документация ко всем блокам
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
  # ack_cmd: bool = field(default=None, metadata={'base_type': 'boolean', 'read_only': False})
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
  # t_control_value: int = field(default=None, metadata={'base_type': 'integer', 'read_only': False})
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
  commands_queue = queue.Queue()
  commands_seq_no = 0
  commands_seq_no_lock = threading.Lock()
  updates_seq_no = 0
  updates_seq_no_lock = threading.Lock()
  properties: Properties
  properties_lock = threading.Lock()

  def get_property(self, name: str):
    """Метод - получение свойств из хранилища"""
    with self.properties_lock:
      return getattr(self.properties, name)

  def update_property(self, name: str, value) -> None:
    """Метод - обновление свойств в хранилище, если изменены"""
    with self.properties_lock:
      old_value = getattr(self.properties, name)
      if value != old_value:
        setattr(self.properties, name, value)


class KeepAliveThread(threading.Thread):
  """Поток для периодической отправки запросов на АС для поддержания связи.

     Запросы представляют из себя POST или PUT запросы на АС с информацией
     об этом сервере. Т.е. АС из этих запросов извлекает и сохраняет информацию
     о том, куда в последствии отправлять данные, т.е. на этот сервер.
     Периодичность по-умолчанию 10 секунд.  
  """
  
  _KEEP_ALIVE_INTERVAL = 10.0

  def __init__(self):
    self.run_lock = threading.Condition()
    self._alive = False
    sock = None
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
      sock.connect(('10.255.255.255', 1))
      local_ip = sock.getsockname()[0]
    finally:
      if sock:
        sock.close()
    self._headers = {
      'Accept': 'application/json',
      'Connection': 'Keep-Alive',
      'Content-Type': 'application/json',
      'Host': _parsed_args.ip,
      'Accept-Encoding': 'gzip'
    }
    self._json = {
      'local_reg': {
        'ip': local_ip,
        'notify': 0,
        'port': _parsed_args.port,
        'uri': "/local_lan"
      }
    }
    super(KeepAliveThread, self).__init__(name='Keep Alive thread')

  @retry(exceptions=ConnectionError, delay=0.5, max_delay=20, backoff=1.5)
  def _establish_connection(self, conn: HTTPConnection) -> None:
    '''Метод - установка соединения (отправка запросов)'''
    method = 'PUT' if self._alive else 'POST'
    try:
      conn.request(method, '/local_reg.json', json.dumps(self._json), self._headers)
      resp = conn.getresponse()
      if resp.status != HTTPStatus.ACCEPTED:
        raise ConnectionError('Recieved invalid response for local_reg: ' + repr(resp))
      resp.read()
    except:
      self._alive = False
      raise
    finally:
      conn.close()
    self._alive = True

  def run(self) -> None:
    '''Метод - Создание и установка соединения'''
    with self.run_lock:
      try:
        conn = HTTPConnection(_parsed_args.ip, timeout=5)
      except InvalidURL:
        _httpd.shutdown()
        return
      while True:
        try:
          self._establish_connection(conn)
        except:
          _httpd.shutdown()
          return
        self._json['local_reg']['notify'] = int(_data.commands_queue.qsize() > 0 or self.run_lock.wait(self._KEEP_ALIVE_INTERVAL))

class QueryStatusThread(threading.Thread):
  """Поток для постановки в очередь команд на запрос значений всех свойств АС.
  
     Очередь команд будет обработана только после запуска потока KeepAlive
     и сервера HTTP для обмена данными с АС.
  """
  
  _STATUS_UPDATE_INTERVAL = 600.0
  _WAIT_FOR_EMPTY_QUEUE = 10.0

  def __init__(self):
    self._next_command_id = 0
    super(QueryStatusThread, self).__init__(name='Query Status thread')

  def run(self) -> None:
    '''Метод - для всех свойств АС формирование данных для запроса и постановка в очередь'''
    while True:
      # In case the AC is stuck, and not fetching commands, avoid flooding
      # the queue with status updates.
      while _data.commands_queue.qsize() > 10:
        time.sleep(self._WAIT_FOR_EMPTY_QUEUE)
      for data_field in fields(_data.properties):
        command = {
          'cmds': [{
            'cmd': {
              'method': 'GET',
              'resource': 'property.json?name=' + data_field.name,
              'uri': '/local_lan/property/datapoint.json',
              'data': '',
              'cmd_id': self._next_command_id,
            }
          }]
        }
        self._next_command_id += 1
        _data.commands_queue.put_nowait((command, None))
      if _keep_alive:
        with _keep_alive.run_lock:
          _keep_alive.run_lock.notify()
      time.sleep(self._STATUS_UPDATE_INTERVAL)

class HTTPRequestHandler(BaseHTTPRequestHandler):
  """Класс - Обработчики запросов на этот http сервер"""

  def do_HEAD(self, code: HTTPStatus = HTTPStatus.OK) -> None:
    """Установка статуса ответа и заголовка ответа 'Content-type' """
    self.send_response(code)
    if code == HTTPStatus.OK:
      self.send_header('Content-type', 'application/json')
    self.end_headers()

  def do_GET(self) -> None:
    """Метод - Обработка GET запросов."""
    parsed_url = urlparse(self.path)
    query = parse_qs(parsed_url.query)
    print(query)
    handler = self._HANDLERS_MAP.get(parsed_url.path)
    if handler:
      handler(self, parsed_url.path, query, {})
      return
    self.do_HEAD(HTTPStatus.NOT_FOUND)

  def do_POST(self):
    """Метод - Обработка POST запросов."""
    content_length = int(self.headers['Content-Length'])
    post_data = self.rfile.read(content_length)
    parsed_url = urlparse(self.path)
    query = parse_qs(parsed_url.query)
    data = json.loads(post_data)
    handler = self._HANDLERS_MAP.get(parsed_url.path)
    if handler:
      handler(self, parsed_url.path, query, data)
      return
    self.do_HEAD(HTTPStatus.NOT_FOUND)

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
      key = data['key_exchange']
      if key['ver'] != 1 or key['proto'] != 1 or key.get('sec'):
        raise KeyError()
      _config.lan_config.random_1 = key['random_1']
      _config.lan_config.time_1 = key['time_1']
    except KeyError:
      self.do_HEAD(HTTPStatus.BAD_REQUEST)
      return
    if key['key_id'] != _config.lan_config.lanip_key_id:
      self.do_HEAD(HTTPStatus.NOT_FOUND)
      return
    _config.lan_config.random_2 = ''.join(
        random.choices(string.ascii_letters + string.digits, k=16))
    _config.lan_config.time_2 = time.monotonic_ns() % 2**40
    _config.update()
    self.do_HEAD(HTTPStatus.OK)
    self._write_json({"random_2": _config.lan_config.random_2,"time_2": _config.lan_config.time_2})

  def command_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает запрос команды.

       Срабатывает при GET запросе со стороны АС на адрес
       /local_lan/commands.json

      Запрос поступает от AC. Метод принимает команду из очереди,
      формирует JSON, шифрует,подписывает его, и передает его в АС.
    """
    command = {}
    with _data.commands_seq_no_lock:
      command['seq_no'] = _data.commands_seq_no
      _data.commands_seq_no += 1
    try:
      command['data'], property_updater = _data.commands_queue.get_nowait()
    except queue.Empty:
      command['data'], property_updater = {}, None
    self.do_HEAD(HTTPStatus.OK)
    self._write_json(encrypt_and_sign(command))
    if property_updater:
      property_updater()

  def property_update_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает запрос на обновление свойств.

       Срабатывает при POST запросе со стороны АС на адрес
       /local_lan/property/datapoint.json

       Расшифровывает, проверяет и помещает значение в локальное хранилище свойств.
    """
    try:
      update = decrypt_and_validate(data)
    except Error:
      self.do_HEAD(HTTPStatus.BAD_REQUEST)
      return
    self.do_HEAD(HTTPStatus.OK)
    with _data.updates_seq_no_lock:
      # Every once in a while the sequence number is zeroed out, so accept it.
      # if _data.updates_seq_no > update['seq_no'] and update['seq_no'] > 0:
      #   logging.error('Stale update found %d. Last update used is %d.',
      #                 (update['seq_no'], _data.updates_seq_no)) 
      #   return  # Old update
      _data.updates_seq_no = update['seq_no']
    name = update['data']['name']
    data_type = _data.properties.get_type(name)
    value = data_type(update['data']['value'])
    _data.update_property(name, value)
    
  def get_status_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает запрос на получение свойств.

       Срабатывает при GET запросе со стороны браузера или умного дома на адрес
       /status

       Возвращает текущее внутренне сохраненное состояние АС из хранилища данных.
    """
    with _data.properties_lock:
      data = _data.properties.to_dict()
    self.do_HEAD(HTTPStatus.OK)
    self._write_json(data)

  def queue_command_handler(self, path: str, query: dict, data: dict) -> None:
    """Метод - Обрабатывает запрос на постановку в очередь команды для АС.

       Срабатывает при GET запросе со стороны браузера или умного дома на адрес
       /command

       Разбирает запрос и отправляет в очередь команд свойства и значения, которое нужно изменить
    """
    try:
      queue_command(query['property'][0], query['value'][0])
    except:
      self.do_HEAD(HTTPStatus.BAD_REQUEST)
      return
    self.do_HEAD(HTTPStatus.OK)
    self._write_json({'queued commands': _data.commands_queue.qsize()})

  def _write_json(self, data: dict) -> None:
    """Отправить данные в виде JSON."""
    self.wfile.write(json.dumps(data).encode('utf-8'))

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

  if _data.properties.get_read_only(name):
    raise Error('Cannot update read-only property "{}".'.format(name))
  data_type = _data.properties.get_type(name)
  base_type = _data.properties.get_base_type(name)
  if issubclass(data_type, enum.Enum):
    data_value = data_type[value].value
  elif data_type is int and type(value) is str and '.' in value:
    # Round rather than fail if the input is a float.
    # This is commonly the case for temperatures converted by HA from Celsius.
    data_value = round(float(value))
  else:
    data_value = data_type(value)
  command = {
    'properties': [{
      'property': {
        'base_type': base_type,
        'name': name,
        'value': data_value,
        'id': ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
      }
    }]
  }
  # There are (usually) no acks on commands, so also queue an update to the
  # property, to be run once the command is sent.
  typed_value = data_type[value] if issubclass(data_type, enum.Enum) else data_value
  property_updater = lambda: _data.update_property(name, typed_value)
  _data.commands_queue.put_nowait((command, property_updater))

  # Handle turning on FastColdHeat
  if name == 't_temp_heatcold' and typed_value is FastColdHeat.ON:
    queue_command('t_fan_speed', 'AUTO', True)
    queue_command('t_fan_mute', 'OFF', True)
    queue_command('t_sleep', 'STOP', True)
    queue_command('t_temp_eight', 'OFF', True)
  if not recursive:
    with _keep_alive.run_lock:
      _keep_alive.run_lock.notify()

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


if __name__ == '__main__':
    _parsed_args = ParseArguments() # создание пространства имен с аргументами запуска  # type: argparse.Namespace
    
    _config = Config() # создание объекта с набором ключей шифрования/дешифрования информации при обмене с АС
    
    _data = Data(properties=AcProperties()) # создание объекта хранилаща свойств АС с дефолтными значениями
       
    _keep_alive = None # удаление потока keep_alive type: typing.Optional[KeepAliveThread]

    query_status = QueryStatusThread() # создание потока - очередь запросов свойств АС
    query_status.start() # запуск потока

    _keep_alive = KeepAliveThread() # создание потока поддержки связи с АС
    _keep_alive.start() # запуск потока

    _httpd = HTTPServer(('', _parsed_args.port), HTTPRequestHandler) # создание http сервера, передача номера порта, на котором будет работать сервер и имя класса обработчика событий
    try:
      _httpd.serve_forever() # запуск http сервера в потоке
    except KeyboardInterrupt:
      pass
      _httpd.server_close() # остановка http сервера

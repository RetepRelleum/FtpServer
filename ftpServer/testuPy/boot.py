# This is script that run when device boot up or wake from sleep.

import machine, sdcard,os
import network


def do_connect():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print('connecting to network...')
        wlan.connect('yjv-55549', 'sijo-f10a-rwrm-n69j')
        while not wlan.isconnected():
            pass
        print('network config:', wlan.ifconfig())
    return wlan.ifconfig()[0]
ip=do_connect()

sd = sdcard.SDCard(machine.SPI(1, sck=machine.Pin(18), mosi=machine.Pin(23),
                   miso=machine.Pin(19)), machine.Pin(4))
os.mount(sd, "/sd")
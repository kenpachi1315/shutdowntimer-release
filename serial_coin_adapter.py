"""Optional Windows RS-232 coin-slot input for PisoNet.

The coin pulse is sampled from a modem-status input (DSR by default). On the
verified Y-wiring, DTR is asserted as a bias for the shared COIN/DSR line;
RTS controls acceptor-ready/inhibit. Hardware is opt-in through environment
variables so an unknown COM port or wiring harness cannot be driven by default.
"""
from __future__ import annotations

import os
import threading
import time


class SerialCoinAdapter:
    def __init__(self, engine):
        self.engine = engine
        self.port = os.environ.get('PISONET_COIN_PORT', '').strip()
        self.input_line = os.environ.get('PISONET_COIN_INPUT', 'DSR').strip().upper()
        self.active_high = os.environ.get('PISONET_COIN_ACTIVE_HIGH', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        self.rts_ready_high = os.environ.get('PISONET_COIN_RTS_READY_HIGH', '1').strip().lower() in ('1', 'true', 'yes', 'on')
        self.dtr_coin_bias_high = os.environ.get('PISONET_COIN_DTR_HIGH', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        self.poll_ms = max(2, min(20, int(os.environ.get('PISONET_COIN_POLL_MS', '5'))))
        self.connected = False
        self.error = ''
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if not self.port:
            return
        if self.input_line not in ('DSR', 'CTS', 'RI', 'CD'):
            self.error = 'PISONET_COIN_INPUT must be DSR, CTS, RI, or CD'
            self.engine.set_health(False)
            return
        self._thread = threading.Thread(target=self._run, name='PisoNetCoinSerial', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _line_value(self, serial_port):
        return bool(getattr(serial_port, {
            'DSR': 'dsr', 'CTS': 'cts', 'RI': 'ri', 'CD': 'cd'
        }[self.input_line]))

    def _run(self):
        try:
            import serial
        except Exception as exc:
            self.error = 'pyserial is unavailable: ' + str(exc)
            self.engine.set_health(False)
            return

        while not self._stop.is_set():
            port = None
            try:
                # Set both outputs before opening the port to avoid a brief
                # default RTS/DTR assertion. RTS must start inhibited; DTR may
                # be asserted to bias the COIN/DSR Y-line when explicitly set.
                port = serial.Serial(port=None, baudrate=9600, timeout=0, write_timeout=0.2)
                port.rts = not self.rts_ready_high
                port.dtr = self.dtr_coin_bias_high
                port.port = self.port
                port.open()
                last_active = self._line_value(port) == self.active_high
                if not self.engine.healthy:
                    self.engine.set_health(True)
                self.connected = True
                self.error = ''
                last_ready = None
                while not self._stop.is_set():
                    engine_state = self.engine.status()
                    ready = bool(engine_state['owner'] and not engine_state['inhibited'] and engine_state['healthy'])
                    if ready != last_ready:
                        port.rts = self.rts_ready_high if ready else not self.rts_ready_high
                        last_ready = ready
                    active = self._line_value(port) == self.active_high
                    now_ms = time.monotonic() * 1000
                    if ready and active != last_active:
                        try:
                            self.engine.edge(active, now_ms)
                        except Exception as exc:
                            if str(exc) != 'COIN_INPUT_INHIBITED':
                                raise
                    if ready:
                        self.engine.poll(now_ms)
                    last_active = active
                    time.sleep(self.poll_ms / 1000)
            except Exception as exc:
                self.connected = False
                self.error = str(exc)[:240]
                self.engine.set_health(False)
                if port is not None:
                    try:
                        port.rts = not self.rts_ready_high
                        port.dtr = False
                        port.close()
                    except Exception:
                        pass
                self._stop.wait(2)
            finally:
                if port is not None:
                    try:
                        port.rts = not self.rts_ready_high
                        port.dtr = False
                        port.close()
                    except Exception:
                        pass
                self.connected = False

    def status(self):
        return {
            'configured': bool(self.port),
            'connected': self.connected,
            'port': self.port or None,
            'input_line': self.input_line if self.port else None,
            'input_active': 'high' if self.active_high else 'low',
            'rts_ready_level': 'high' if self.rts_ready_high else 'low',
            'dtr_coin_bias_level': 'high' if self.dtr_coin_bias_high else 'low',
            'error': self.error,
        }

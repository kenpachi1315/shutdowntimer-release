"""Server-owned pulse decoder for PisoNet M2D. Uses monotonic milliseconds."""
import threading
from functools import wraps
from dataclasses import dataclass, field
class SignalError(ValueError): pass

def _synchronized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return call

@dataclass
class DecoderConfig:
    expected_pulse_width_ms:int=50
    tolerance_ratio:float=0.50
    gap_ms:int=300
    max_pulses:int=30
    pulse_values_centavos:dict=field(default_factory=lambda:{1:100,5:500,10:1000,20:2000})
class CoinSignalEngine:
    def __init__(self,on_coin,config=None):
        self._lock=threading.RLock()
        self.cfg=config or DecoderConfig()
        if self.cfg.expected_pulse_width_ms not in (20,50,100): raise ValueError("Pulse width must be 20, 50, or 100 ms")
        self.on_coin=on_coin; self.owner=None; self.session_id=None; self.healthy=True; self.inhibited=True
        self.high=False; self.rise=None; self.last_fall=None; self.widths=[]; self.invalid=None; self.last_ms=None; self.events=[]
    def _time(self,ms):
        if self.last_ms is not None and ms<self.last_ms: raise SignalError("NON_MONOTONIC_TIMESTAMP")
        self.last_ms=ms
    @_synchronized
    def reserve(self,pc_id,sid):
        if not self.healthy: raise SignalError("HARDWARE_FAULT")
        if self.owner is not None: raise SignalError("COIN_SLOT_BUSY")
        self.owner,self.session_id=pc_id,sid; self.inhibited=False
    @_synchronized
    def restore_reservation_inhibited(self,pc_id,sid):
        """Restore a persisted insertion after restart without reopening input."""
        if self.owner is not None and (self.owner != pc_id or self.session_id != sid):
            raise SignalError("COIN_SLOT_BUSY")
        self.owner,self.session_id=pc_id,sid
        self.inhibited=True
        # In-flight electrical edges cannot be trusted across a process restart;
        # previously decoded coin batches remain persisted in the database.
        self.high=False; self.rise=None; self.last_fall=None; self.widths=[]; self.invalid=None
    def _discard(self,reason):
        if self.widths or self.high: self.events.append({"event":"discarded","reason":reason,"pulses":len(self.widths)})
        self.widths=[]; self.invalid=None; self.last_fall=None
    @_synchronized
    def cancel_if_idle(self,sid):
        """Drop an empty insertion reservation without discarding a coin pulse."""
        if self.session_id is None:
            return False
        if sid != self.session_id:
            raise SignalError("SESSION_NOT_OWNER")
        if self.high or self.last_fall is not None or self.widths:
            raise SignalError("COIN_PULSE_IN_PROGRESS")
        self.owner=self.session_id=None; self.inhibited=True; self.rise=None
        return True
    @_synchronized
    def release(self,sid):
        if sid!=self.session_id: raise SignalError("SESSION_NOT_OWNER")
        self._discard("reservation_released"); self.owner=self.session_id=None; self.inhibited=True; self.high=False; self.rise=None
    @_synchronized
    def set_health(self,healthy):
        self.healthy=bool(healthy)
        if not self.healthy:
            self.inhibited=True; self._discard("hardware_fault"); self.high=False; self.rise=None
        else: self.inhibited=True
    @_synchronized
    def edge(self,high,ms):
        self._time(ms)
        if not self.healthy: raise SignalError("HARDWARE_FAULT")
        if self.inhibited or self.session_id is None: raise SignalError("COIN_INPUT_INHIBITED")
        high=bool(high)
        if high==self.high: return None
        if high:
            self.high=True; self.rise=ms; return {"event":"rising"}
        if self.rise is None: raise SignalError("FALLING_EDGE_WITHOUT_RISING_EDGE")
        width=ms-self.rise; self.high=False; self.rise=None
        lo=max(8,self.cfg.expected_pulse_width_ms*(1-self.cfg.tolerance_ratio))
        hi=min(250,self.cfg.expected_pulse_width_ms*(1+self.cfg.tolerance_ratio))
        if not lo<=width<=hi: self.invalid="PULSE_WIDTH_OUT_OF_RANGE"
        else: self.widths.append(width)
        if len(self.widths)>self.cfg.max_pulses: self.invalid="TOO_MANY_PULSES"
        self.last_fall=ms
        return {"event":"falling","width_ms":width,"valid":self.invalid is None}
    @_synchronized
    def poll(self,ms):
        self._time(ms)
        if self.inhibited or not self.healthy or self.high or self.last_fall is None or ms-self.last_fall<self.cfg.gap_ms: return None
        count=len(self.widths); invalid=self.invalid; self.widths=[]; self.invalid=None; self.last_fall=None
        if invalid or count==0:
            self.events.append({"event":"rejected","reason":invalid or "EMPTY_TRAIN"}); return None
        cents=self.cfg.pulse_values_centavos.get(count)
        if cents is None: self.events.append({"event":"unmapped","pulses":count}); return None
        sid=self.session_id
        if not sid or self.inhibited or not self.healthy: return None
        self.on_coin(sid,cents,count)
        result={"session_id":sid,"pulse_count":count,"denomination_centavos":cents}
        self.events.append({"event":"coin_decoded",**result}); return result
    @_synchronized
    def status(self):
        return {"owner":self.owner,"session_id":self.session_id,"healthy":self.healthy,"inhibited":self.inhibited,
                "coin_line_high":self.high,"pending_pulses":len(self.widths),"pulse_train_open":self.last_fall is not None or self.high}

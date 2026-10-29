"""Transient per-job test sessions; never persist or log values."""
import threading
import time

TTL_SECONDS=120
EXPIRED_MESSAGE='Sesi uji tidak tersedia atau kedaluwarsa; buat run baru.'

class SessionVault:
    def __init__(self,ttl=TTL_SECONDS,clock=time.monotonic):
        self.lock=threading.RLock();self.entries={};self.ttl=ttl;self.clock=clock
    def put(self,jid,tokens):
        with self.lock:
            if len(self.entries)>=10:raise ValueError('Batas sesi sementara tercapai.')
            timer=threading.Timer(self.ttl,self.discard,args=(jid,));timer.daemon=True
            self.entries[jid]=(self.clock()+self.ttl,tuple(tokens),timer);timer.start()
    def alive(self,jid):
        """True while the job still holds unexpired tokens; never returns the values."""
        with self.lock:
            item=self.entries.get(jid)
            return bool(item and item[0]>self.clock())
    def take(self,jid):
        with self.lock:
            item=self.entries.pop(jid,None)
            if item:item[2].cancel()
            if not item or item[0]<=self.clock():raise ValueError(EXPIRED_MESSAGE)
            return item[1]
    def discard(self,jid):
        with self.lock:
            item=self.entries.pop(jid,None)
            if item:item[2].cancel()

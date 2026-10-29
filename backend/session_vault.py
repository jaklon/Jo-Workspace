"""Transient per-job test sessions; never persist or log values."""
import threading
import time

class SessionVault:
    def __init__(self):
        self.lock=threading.RLock();self.entries={}
    def put(self,jid,tokens):
        with self.lock:
            if len(self.entries)>=10:raise ValueError('Batas sesi sementara tercapai.')
            timer=threading.Timer(120,self.discard,args=(jid,));timer.daemon=True
            self.entries[jid]=(time.monotonic()+120,tuple(tokens),timer);timer.start()
    def take(self,jid):
        with self.lock:
            item=self.entries.pop(jid,None)
            if item:item[2].cancel()
            if not item or item[0]<=time.monotonic():raise ValueError('Sesi uji tidak tersedia atau kedaluwarsa; buat run baru.')
            return item[1]
    def discard(self,jid):
        with self.lock:
            item=self.entries.pop(jid,None)
            if item:item[2].cancel()

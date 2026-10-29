"""Windows AppContainer, zero capabilities, explicit stdio handles, bounded Job Object.

No ordinary-process fallback, shell, caller commands, inherited credentials or workspace mounts.
"""
import asyncio
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
from uuid import uuid4
import zipfile

PREPARE_LOCK = threading.Lock()
PROFILE = 'AgentOS.SecurityMCP.Fixture.v1'


class SandboxError(RuntimeError):pass


def supported():
    if sys.platform!='win32':return False
    try:
        import win32security, win32job, win32pipe
        return bool(win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    except ImportError:return False


def sha_file(path):
    with open(path,'rb') as file:return hashlib.file_digest(file,'sha256').hexdigest()


def sid_for_profile(profile):
    userenv=ctypes.WinDLL('userenv',use_last_error=True)
    create=userenv.CreateAppContainerProfile
    create.argtypes=[W.LPCWSTR,W.LPCWSTR,W.LPCWSTR,ctypes.c_void_p,W.DWORD,ctypes.POINTER(ctypes.c_void_p)]
    create.restype=ctypes.c_long
    derive=userenv.DeriveAppContainerSidFromAppContainerName
    derive.argtypes=[W.LPCWSTR,ctypes.POINTER(ctypes.c_void_p)];derive.restype=ctypes.c_long
    sid=ctypes.c_void_p()
    result=create(profile,'Jo Workspace MCP fixture','Offline synthetic MCP runner',None,0,ctypes.byref(sid))
    if result and (result & 0xffffffff)!=0x800700b7:raise SandboxError('AppContainer profile unavailable.')
    if result and derive(profile,ctypes.byref(sid)):raise SandboxError('AppContainer SID unavailable.')
    return sid


def sid_object(pointer):
    import win32security
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    adv.GetLengthSid.argtypes=[ctypes.c_void_p];adv.GetLengthSid.restype=W.DWORD
    return win32security.SID(ctypes.string_at(pointer,adv.GetLengthSid(pointer)))


def free_sid(pointer):
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    adv.FreeSid.argtypes=[ctypes.c_void_p];adv.FreeSid.restype=ctypes.c_void_p
    adv.FreeSid(pointer)


def acl(path, sid, writable=False):
    import win32api, win32security, ntsecuritycon
    token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32security.TOKEN_QUERY)
    try:owner=win32security.GetTokenInformation(token,win32security.TokenUser)[0]
    finally:token.Close()
    system=win32security.CreateWellKnownSid(win32security.WinLocalSystemSid,None)
    dacl=win32security.ACL()
    inherit=win32security.OBJECT_INHERIT_ACE|win32security.CONTAINER_INHERIT_ACE
    for who,rights in [(owner,ntsecuritycon.FILE_ALL_ACCESS),(system,ntsecuritycon.FILE_ALL_ACCESS),
                       (sid,ntsecuritycon.FILE_ALL_ACCESS if writable else ntsecuritycon.FILE_GENERIC_READ|ntsecuritycon.FILE_GENERIC_EXECUTE)]:
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS,inherit,rights,who)
    win32security.SetNamedSecurityInfo(str(path),win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION|win32security.PROTECTED_DACL_SECURITY_INFORMATION,None,None,dacl,None)
    if writable:
        low=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('S:(ML;OICI;NW;;;LW)',1)
        win32security.SetNamedSecurityInfo(str(path),win32security.SE_FILE_OBJECT,0x10,None,None,None,low.GetSecurityDescriptorSacl())


class SandboxRuntime:
    def __init__(self, directory):
        self.root=Path(directory).resolve()/'mcp-sandbox'
        self.runtime=self.root/'runtime'
        self.requests=self.root/'requests'
        self.profile=PROFILE+'.'+hashlib.sha256(str(self.root).casefold().encode()).hexdigest()[:16]

    def prepare(self):
        if not supported():raise SandboxError('Windows AppContainer/pywin32 required. No fallback runner.')
        with PREPARE_LOCK:
            pointer=sid_for_profile(self.profile)
            try:sid=sid_object(pointer)
            finally:free_sid(pointer)
            self.root.mkdir(parents=True,exist_ok=True)
            self.requests.mkdir(exist_ok=True)
            import psutil
            for directory in self.requests.iterdir():
                match=re.fullmatch(r'(\d+)-[a-f0-9-]{36}',directory.name)
                if match and not psutil.pid_exists(int(match[1])):
                    target=directory.resolve()
                    if target.parent==self.requests.resolve():shutil.rmtree(target,ignore_errors=True)
            frozen=bool(getattr(sys,'frozen',False))
            base=Path(sys._MEIPASS)/'fixture-python' if frozen else Path(sys.base_prefix)
            source=Path(__file__).with_name('mcp_fixture_server.py')
            expected={'python':str(base),'version':sys.version,'server_sha':sha_file(source)}
            manifest=self.runtime/'manifest.json'
            if not manifest.is_file() or json.loads(manifest.read_text(encoding='utf-8')).get('identity')!=expected:
                self.runtime.mkdir(exist_ok=True)
                if frozen and not (base/'stdlib.zip').is_file():raise SandboxError('Bundled isolated Python runtime missing. No fallback runner.')
                for file in [base/'python.exe',*base.glob('*.dll')]:shutil.copy2(file,self.runtime/file.name)
                dlls=self.runtime/'DLLs';dlls.mkdir(exist_ok=True)
                for file in (base/'DLLs').iterdir():
                    if file.suffix.lower() in ('.pyd','.dll'):shutil.copy2(file,dlls/file.name)
                skip={'site-packages','test','idlelib','tkinter','turtledemo','ensurepip','venv','lib2to3','__pycache__'}
                if frozen:shutil.copy2(base/'stdlib.zip',self.runtime/'stdlib.zip')
                else:
                    with zipfile.ZipFile(self.runtime/'stdlib.zip','w',compression=zipfile.ZIP_STORED) as archive:
                        for file in (base/'Lib').rglob('*.py'):
                            rel=file.relative_to(base/'Lib')
                            if not any(part in skip for part in rel.parts):archive.write(file,str(rel).replace('\\','/'))
                (self.runtime/'python311._pth').write_text('stdlib.zip\nDLLs\n.\n',encoding='ascii')
                shutil.copy2(source,self.runtime/'mcp_fixture_server.py')
                hashes={str(file.relative_to(self.runtime)):sha_file(file) for file in self.runtime.rglob('*') if file.is_file() and file.name!='manifest.json'}
                manifest.write_text(json.dumps({'identity':expected,'hashes':hashes}),encoding='utf-8')
                acl(self.runtime,sid)
                for file in self.runtime.rglob('*'):acl(file,sid)
            data=json.loads(manifest.read_text(encoding='utf-8'))
            for relative,expected_hash in data['hashes'].items():
                file=(self.runtime/relative).resolve()
                if not file.is_relative_to(self.runtime) or sha_file(file)!=expected_hash:raise SandboxError('Isolated runtime integrity mismatch.')
            if sha_file(self.runtime/'mcp_fixture_server.py')!=expected['server_sha']:raise SandboxError('Fixture adapter changed.')
            return self

    def start(self):
        return AppContainerProcess(self)


class STARTUPINFO(ctypes.Structure):
    _fields_=[('cb',W.DWORD),('lpReserved',W.LPWSTR),('lpDesktop',W.LPWSTR),('lpTitle',W.LPWSTR),
              ('dwX',W.DWORD),('dwY',W.DWORD),('dwXSize',W.DWORD),('dwYSize',W.DWORD),
              ('dwXCountChars',W.DWORD),('dwYCountChars',W.DWORD),('dwFillAttribute',W.DWORD),
              ('dwFlags',W.DWORD),('wShowWindow',W.WORD),('cbReserved2',W.WORD),('lpReserved2',ctypes.c_void_p),
              ('hStdInput',W.HANDLE),('hStdOutput',W.HANDLE),('hStdError',W.HANDLE)]


class STARTUPINFOEX(ctypes.Structure):
    _fields_=[('StartupInfo',STARTUPINFO),('lpAttributeList',ctypes.c_void_p)]


class PROCESSINFO(ctypes.Structure):
    _fields_=[('hProcess',W.HANDLE),('hThread',W.HANDLE),('dwProcessId',W.DWORD),('dwThreadId',W.DWORD)]


class SECURITYCAPABILITIES(ctypes.Structure):
    _fields_=[('AppContainerSid',ctypes.c_void_p),('Capabilities',ctypes.c_void_p),('CapabilityCount',W.DWORD),('Reserved',W.DWORD)]


class AppContainerProcess:
    def __init__(self,runtime):
        import win32api, win32security, win32job, win32pipe
        import pywintypes
        self.directory=runtime.requests/(str(os.getpid())+'-'+str(uuid4()))
        self.directory.mkdir()
        self.process=None;self.job=None;self.handles=[];self.closed=False;self.buffer=b'';self.total=0
        pointer=sid_for_profile(runtime.profile)
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel=kernel
        kernel.CreateProcessW.argtypes=[W.LPCWSTR,W.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,W.BOOL,W.DWORD,ctypes.c_void_p,W.LPCWSTR,ctypes.c_void_p,ctypes.POINTER(PROCESSINFO)]
        kernel.CreateProcessW.restype=W.BOOL
        kernel.InitializeProcThreadAttributeList.argtypes=[ctypes.c_void_p,W.DWORD,W.DWORD,ctypes.POINTER(ctypes.c_size_t)]
        kernel.InitializeProcThreadAttributeList.restype=W.BOOL
        kernel.UpdateProcThreadAttribute.argtypes=[ctypes.c_void_p,W.DWORD,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p]
        kernel.UpdateProcThreadAttribute.restype=W.BOOL
        kernel.DeleteProcThreadAttributeList.argtypes=[ctypes.c_void_p]
        kernel.CloseHandle.argtypes=[W.HANDLE]
        kernel.ResumeThread.argtypes=[W.HANDLE];kernel.ResumeThread.restype=W.DWORD
        kernel.TerminateProcess.argtypes=[W.HANDLE,W.UINT]
        kernel.GetExitCodeProcess.argtypes=[W.HANDLE,ctypes.POINTER(W.DWORD)]
        kernel.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];kernel.WaitForSingleObject.restype=W.DWORD
        attributes=None
        phase="prepare"
        child_handles=[]
        try:
            acl(self.directory,sid_object(pointer),True)
            sa=pywintypes.SECURITY_ATTRIBUTES();sa.bInheritHandle=True
            child_in,self.stdin=win32pipe.CreatePipe(sa,4096)
            self.stdout,child_out=win32pipe.CreatePipe(sa,4096)
            self.stderr,child_err=win32pipe.CreatePipe(sa,4096)
            self.handles=[self.stdin,self.stdout,self.stderr]
            child_handles=[child_in,child_out,child_err]
            for handle in self.handles:win32api.SetHandleInformation(handle,1,0)
            count=ctypes.c_size_t()
            kernel.InitializeProcThreadAttributeList(None,2,0,ctypes.byref(count))
            attributes=ctypes.create_string_buffer(count.value)
            if not kernel.InitializeProcThreadAttributeList(attributes,2,0,ctypes.byref(count)):raise ctypes.WinError(ctypes.get_last_error())
            caps=SECURITYCAPABILITIES(pointer,None,0,0)
            inherited=(W.HANDLE*3)(*[int(h) for h in child_handles])
            for key,value in [(0x20009,caps),(0x20002,inherited)]:
                if not kernel.UpdateProcThreadAttribute(attributes,0,key,ctypes.byref(value),ctypes.sizeof(value),None,None):raise ctypes.WinError(ctypes.get_last_error())
            info=STARTUPINFOEX();info.StartupInfo.cb=ctypes.sizeof(info);info.lpAttributeList=ctypes.cast(attributes,ctypes.c_void_p)
            info.StartupInfo.dwFlags=0x100
            info.StartupInfo.hStdInput=int(child_in);info.StartupInfo.hStdOutput=int(child_out);info.StartupInfo.hStdError=int(child_err)
            exe=runtime.runtime/'python.exe'
            command=ctypes.create_unicode_buffer(subprocess.list2cmdline([str(exe),'-I','-S','-B',str(runtime.runtime/'mcp_fixture_server.py')]))
            environment=ctypes.create_unicode_buffer('LOCALAPPDATA='+os.environ['LOCALAPPDATA']+'\0SystemRoot='+os.environ.get('SystemRoot','C:\\Windows')+'\0TEMP='+str(self.directory)+'\0TMP='+str(self.directory)+'\0windir='+os.environ.get('SystemRoot','C:\\Windows')+'\0\0')
            pi=PROCESSINFO()
            phase="CreateProcess"
            if not kernel.CreateProcessW(str(exe),command,None,None,True,0x80000|0x8000000|0x400|4,environment,str(self.directory),ctypes.byref(info),ctypes.byref(pi)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.process=pi.hProcess;self.pid=pi.dwProcessId
            try:
                phase="JobObject"
                self.job=win32job.CreateJobObject(None,'')
                limits=win32job.QueryInformationJobObject(self.job,win32job.JobObjectExtendedLimitInformation)
                limits['BasicLimitInformation']['LimitFlags']=0x2000|0x100|0x8|0x2
                limits['BasicLimitInformation']['ActiveProcessLimit']=1
                limits['BasicLimitInformation']['PerProcessUserTimeLimit']=30_000_000
                limits['ProcessMemoryLimit']=256*1024*1024
                win32job.SetInformationJobObject(self.job,win32job.JobObjectExtendedLimitInformation,limits)
                win32job.AssignProcessToJobObject(self.job,int(self.process))
                phase="Token"
                token=win32security.OpenProcessToken(int(self.process),win32security.TOKEN_QUERY)
                try:
                    # TOKEN_INFORMATION_CLASS TokenIsAppContainer = 29.
                    adv=ctypes.WinDLL('advapi32',use_last_error=True)
                    adv.GetTokenInformation.argtypes=[W.HANDLE,ctypes.c_int,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD)]
                    value=W.DWORD();size=W.DWORD()
                    if not adv.GetTokenInformation(int(token),29,ctypes.byref(value),ctypes.sizeof(value),ctypes.byref(size)) or value.value!=1:
                        raise SandboxError('Process is not an AppContainer; launch refused.')
                finally:token.Close()
                phase="ResumeThread"
                if kernel.ResumeThread(pi.hThread)==0xffffffff:raise ctypes.WinError(ctypes.get_last_error())
            finally:kernel.CloseHandle(pi.hThread)
        except Exception as exc:
            self.close()
            raise SandboxError('AppContainer launch failed at '+phase+': '+str(exc)[:250]) from None
        finally:
            for handle in child_handles:handle.Close()
            if attributes:kernel.DeleteProcThreadAttributeList(attributes)
            free_sid(pointer)

    def send(self,message):
        import win32file
        win32file.WriteFile(self.stdin,(json.dumps(message,separators=(',',':'))+'\n').encode('utf-8'))

    def drain(self,limit):
        import win32pipe,win32file
        for handle,stdout in [(self.stdout,True),(self.stderr,False)]:
            try:available=win32pipe.PeekNamedPipe(handle,0)[1]
            except Exception:available=0
            if available:
                _,data=win32file.ReadFile(handle,min(available,65536))
                self.total+=len(data)
                if self.total>limit:raise SandboxError('OUTPUT_LIMIT')
                if stdout:self.buffer+=data
                elif data:raise SandboxError('Fixture wrote unexpected stderr.')
        if b'\n' in self.buffer:
            line,self.buffer=self.buffer.split(b'\n',1)
            try:return json.loads(line)
            except Exception:raise SandboxError('Invalid MCP JSON-RPC output.') from None
        return None

    def alive(self):
        code=W.DWORD()
        return bool(self.process and self.kernel.GetExitCodeProcess(self.process,ctypes.byref(code)) and code.value==259)

    def close(self):
        if self.closed:return
        self.closed=True
        if self.job:
            import win32job
            win32job.TerminateJobObject(self.job,1)
            self.job.Close();self.job=None
        elif self.process:self.kernel.TerminateProcess(self.process,1)
        if self.process:
            self.kernel.WaitForSingleObject(self.process,1000)
            self.kernel.CloseHandle(self.process);self.process=None
        for handle in self.handles:
            try:handle.Close()
            except Exception:pass
        target=self.directory.resolve()
        if target.parent!=self.directory.parent.resolve():raise SandboxError('Unexpected cleanup path.')
        shutil.rmtree(target,ignore_errors=True)


async def exchange(process,method,params,request_id,guard,deadline,limit=65536):
    await guard()
    process.send({'jsonrpc':'2.0','id':request_id,'method':method,'params':params})
    while time.monotonic()<deadline:
        await guard()
        message=process.drain(limit)
        if message is not None:
            if message.get('jsonrpc')!='2.0' or message.get('id')!=request_id or 'error' in message or 'result' not in message:
                raise SandboxError('Invalid or rejected MCP response.')
            return message['result']
        if not process.alive():raise SandboxError('Isolated MCP process exited unexpectedly.')
        await asyncio.sleep(.025)
    raise SandboxError('TIME_LIMIT')

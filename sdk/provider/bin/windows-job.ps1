# Build-time ownership only. This is not the runtime plugin/native-helper sandbox.
# Windows 10+ atomically assigns the child to a kill-on-close job at creation.
$ErrorActionPreference = 'Stop'
try {
  $request = $env:OMD_BUILD_REQUEST | ConvertFrom-Json
  Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class OmdBuildJob {
  [StructLayout(LayoutKind.Sequential)] struct BasicLimits { public long PerProcessTime,PerJobTime; public uint Flags; public UIntPtr MinimumWorkingSet,MaximumWorkingSet; public uint ActiveProcesses; public UIntPtr Affinity; public uint Priority,Scheduling; }
  [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOperations,WriteOperations,OtherOperations,ReadBytes,WriteBytes,OtherBytes; }
  [StructLayout(LayoutKind.Sequential)] struct Limits { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup { public uint cb; public string Reserved,Desktop,Title; public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags; public ushort Show,ReservedSize; public IntPtr ReservedBytes,Input,Output,Error; }
  [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup Info; public IntPtr Attributes; }
  [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process,Thread; public uint ProcessId,ThreadId; }
  [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr security,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref Limits limits,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
  [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
  [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool CreateProcess(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref StartupEx startup,out ProcessInfo process);
  [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForMultipleObjects(uint count,IntPtr[] handles,bool all,uint milliseconds);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint id);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  static void Check(bool ok){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());}
  static string Quote(string value){
    var s=new StringBuilder("\"");int slashes=0;
    foreach(char c in value){if(c=='\\'){slashes++;continue;}if(c=='\"'){s.Append('\\',slashes*2+1);s.Append(c);}else{s.Append('\\',slashes);s.Append(c);}slashes=0;}
    s.Append('\\',slashes*2);s.Append('"');return s.ToString();
  }
  public static int Run(string program,string[] args,string directory,IDictionary environment,uint parentId){
    IntPtr parent=IntPtr.Zero,job=IntPtr.Zero,list=IntPtr.Zero,jobValue=IntPtr.Zero,block=IntPtr.Zero;bool initialized=false;ProcessInfo child=new ProcessInfo();
    try{
      parent=OpenProcess(0x00101000,false,parentId);Check(parent!=IntPtr.Zero);
      long parentCreated,parentExited,parentKernel,parentUser,selfCreated,selfExited,selfKernel,selfUser;
      Check(GetProcessTimes(parent,out parentCreated,out parentExited,out parentKernel,out parentUser));
      Check(GetProcessTimes(GetCurrentProcess(),out selfCreated,out selfExited,out selfKernel,out selfUser));
      // Reject a reused PID if the invoking process died before this wrapper initialized.
      Check(parentCreated<=selfCreated);
      job=CreateJobObject(IntPtr.Zero,null);Check(job!=IntPtr.Zero);
      var limits=new Limits();limits.Basic.Flags=0x2000;Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(Limits))));
      IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);Check(size!=IntPtr.Zero);
      list=Marshal.AllocHGlobal(size);Check(InitializeProcThreadAttributeList(list,1,0,ref size));initialized=true;
      jobValue=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobValue,job);
      Check(UpdateProcThreadAttribute(list,0,new IntPtr(0x2000D),jobValue,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
      var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
      foreach(DictionaryEntry pair in environment){var key=(string)pair.Key;if(key!="OMD_BUILD_REQUEST")env[key]=Convert.ToString(pair.Value);}
      var encoded=new StringBuilder();foreach(var pair in env)encoded.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');encoded.Append('\0');if(env.Count==0)encoded.Append('\0');
      block=Marshal.StringToHGlobalUni(encoded.ToString());
      var startup=new StartupEx();startup.Info.cb=(uint)Marshal.SizeOf(typeof(StartupEx));startup.Info.Flags=0x100;startup.Info.Input=GetStdHandle(-10);startup.Info.Output=GetStdHandle(-11);startup.Info.Error=GetStdHandle(-12);startup.Attributes=list;
      var command=new StringBuilder(Quote(program));foreach(var arg in args)command.Append(' ').Append(Quote(arg));
      // EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW.
      Check(CreateProcess(program,command,IntPtr.Zero,IntPtr.Zero,true,0x00080000|0x00000400|0x08000000,block,directory,ref startup,out child));
      uint waited=WaitForMultipleObjects(2,new IntPtr[]{child.Process,parent},false,0xffffffff);if(waited==1)return 125;Check(waited==0);uint code;Check(GetExitCodeProcess(child.Process,out code));return unchecked((int)code);
    }finally{
      // Kernel job membership survives intermediate parent exits; no PID-tree walk.
      if(job!=IntPtr.Zero)CloseHandle(job);
      if(parent!=IntPtr.Zero)CloseHandle(parent);
      if(child.Thread!=IntPtr.Zero)CloseHandle(child.Thread);if(child.Process!=IntPtr.Zero)CloseHandle(child.Process);
      if(initialized)DeleteProcThreadAttributeList(list);if(list!=IntPtr.Zero)Marshal.FreeHGlobal(list);if(jobValue!=IntPtr.Zero)Marshal.FreeHGlobal(jobValue);if(block!=IntPtr.Zero)Marshal.FreeHGlobal(block);
    }
  }
}
'@
  $childEnvironment = @{}
  if ($null -eq $request.environment) {
    $childEnvironment = [System.Environment]::GetEnvironmentVariables()
  } else {
    foreach ($property in $request.environment.PSObject.Properties) { $childEnvironment[$property.Name] = [string]$property.Value }
  }
  $code = [OmdBuildJob]::Run([string]$request.program,[string[]]$request.arguments,[string]$request.directory,$childEnvironment,[uint32]$request.parent_process_id)
  exit $code
} catch {
  [Console]::Error.WriteLine('The Windows build worker could not start in its required process job. Use Windows 10 or newer with Windows PowerShell available.')
  exit 126
}

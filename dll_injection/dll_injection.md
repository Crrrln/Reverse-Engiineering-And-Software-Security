## Dll injection

### **实验要求**

- [x] 参考[样例代码](https://github.com/fdiskyou/injectAllTheThings)，编写一个dll文件，并能在exe中成功调用（第一步不需要实现远程线程注入）

### **实验过程**

**1. 编写一个dll文件，并能在exe中成功调用（第一步不需要实现远程线程注入）**


编写`dllpoc.cpp`文件
```
#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

//extern "C" __declspec(dllexport) int poc(int code, WPARAM wParam, LPARAM lParam) {
//以C语言方式调用  __declspec(dllexport)通过导出表进行导出，导出函数叫poc
extern "C" __declspec(dllexport) BOOL cuc() {
	

	//为了证明导出表在这
	MessageBox(NULL, L"I am cuc function!", L"2020-11-8!", 0);


	TCHAR szExePath[MAX_PATH];
	TCHAR szInfo[MAX_PATH + 100];
	GetModuleFileName(NULL, szExePath, MAX_PATH);
	wsprintf(szInfo, TEXT("I am in Proccess(%d),Path：%s"), GetCurrentProcessId(), szExePath);
	MessageBox(NULL, szInfo, L"2020-11-8!", 0);

	//假定这里有一个攻击代码 ex 全盘加密

	//return(CallNextHookEx(NULL, code, wParam, lParam));
	return TRUE;
}
//不在导出表
BOOL beijing() {
	MessageBox(NULL, L"POC called!", L"Inject All The Things!", 0);

	//return(CallNextHookEx(NULL, code, wParam, lParam));
	return TRUE;
}
```

新建项目`Project1`，以及源文件`load.c`文件，为了调用dll

```
#include<Windows.h>
#include<stdio.h>
#include<stdlib.h>

typedef BOOL(*CUC_PROC_ADDR)();

int main() {
	HMODULE hmoudle=LoadLibraryA("dllpoc.dll");
	CUC_PROC_ADDR cuc_ptr = (CUC_PROC_ADDR)GetProcAddress(hmoudle, "cuc");
	//获得函数指针,把cuc的地址保存下来
	void* cuc=GetProcAddress(hmoudle,"cuc");
	void* bj = GetProcAddress(hmoudle, "beijing");
	printf("cuc function addr: %p, beijing function addr: %p",cuc,bj);
	cuc_ptr();
}		
```

修改配置类型为`动态库.dll`

![](./img/dll.PNG)

### **实验结果**

1.对项目`injectAllTheThings`进行重新生成，运行`Project1.exe`

![](./img/address.gif)

可以证明，导出函数叫cuc，以C语言方式调用  __declspec(dllexport)通过导出表进行导出，由于`beijing`不是导出函数，故其地址为null

2.查看`Project1.exe`进程的序号和位置，并输出

![](./img/processid.gif)

通过任务管理器验证，此时输出的进程id与位置均正确

![](./img/进程id.PNG)



### **遇到的问题和解决方法**



### **参考资料**
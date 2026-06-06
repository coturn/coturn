/*!
 * Example of use service
 * \author Kang Lin <kl222@126.com>
 *
 * ### Usage:
 *   - Build:
 * 
 *          cd src\apps\relay\windows
 *          mkdir build
 *          cd build
 *          cmake ..
 *          cmake --build .
 *
 *   - Programe:
 * 
 *          cd bin\Debug
 *          dir
 * 
 *          2025/05/29  11:12    <DIR>          .
 *          2025/05/29  11:12    <DIR>          ..
 *          2025/05/29  11:12           148,480 coturn_example.exe
 *          2025/05/29  11:12         3,543,040 coturn_example.pdb
 * 
 *   - Usage:
 * 
 *     ; Show usage
 *     coturn_example.exe -h
 *     ; Using Administrator Privileges to install service
 *     coturn_example.exe -install
 *     ; Using Administrator Privileges to remove service
 *     coturn_example.exe -remove
 * 
 *     ; Viewing Log Events Using the Event Manager
 *     ; Managing coturn services using the service manager
 */

#include "Service.h"
#include "ServiceInstaller.h"
#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <windows.h>

static BOOL g_exit = FALSE;

unsigned long start(int argc, char *argv[]) {
  char msg[1024];
  sprintf_s(msg, 1024, "Start:argc:[%d]:", argc);
  GetServiceLog()(msg);
  for (int i = 0; i < argc; i++) {
    sprintf_s(msg, 1024, " %s", argv[i]);
    GetServiceLog()(msg);
  }
  return 0;
}

unsigned long run() {
  int num = 1;
  GetServiceLog()("run ...");
  do {
    char buf[64];
    sprintf_s(buf, 64, "run %d", num++);
    GetServiceLog()(buf);
    Sleep(1000);
  } while (!g_exit);
  GetServiceLog()("run end");
  return 0;
}

void stop() {
  GetServiceLog()("stop");
  g_exit = TRUE;
}

int main(int argc, char *argv[]) {
  printf("Log file: d:\\coturn_example.log\n");
  SetLogFile("d:\\coturn_example.log");
  GetServiceLog()("main start");
  const char *pServiceName = _T("coturn_example");
  if ((argc > 1) && ((*argv[1] == '-' || (*argv[1] == '/')))) {
    if (_stricmp("install", argv[1] + 1) == 0) {
      printf("Install service ......\n");
      // Install the service when the command is
      // "-install" or "/install".
      InstallService(pServiceName,                     // Name of service
                     pServiceName,                     // Name to display
                     SERVICE_AUTO_START,               // Service start type
                     _T(""),                           // Dependencies, format:  "dep1\0dep2\0\0"
                     _T("NT AUTHORITY\\LocalService"), // Service running account(local server)
                     NULL                              // Password of the account
      );
    } else if (_stricmp("remove", argv[1] + 1) == 0) {
      printf("Remove service ......\n");
      // Uninstall the service when the command is
      // "-remove" or "/remove".
      UninstallService(pServiceName);
    } else {
      printf("%s\nUsage:\n%s\n%s\n%s\n", argv[0],
          "\t-install: install service requires administrator privileges",
          "\t-remove:  remove service requires administrator privileges",
          "\t-h: help");
    }
  } else {
    printf("Run service ......\n");
    ServiceRun(pServiceName, start, run, stop);
  }
  GetServiceLog()("main end");
  return 0;
}
